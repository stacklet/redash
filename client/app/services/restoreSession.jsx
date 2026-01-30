import React from "react";
import Modal from "antd/lib/modal";
import { Auth } from "@/services/auth";

const SESSION_RESTORED_MESSAGE = "redash_session_restored";

export function notifySessionRestored() {
  if (window.opener) {
    window.opener.postMessage({ type: SESSION_RESTORED_MESSAGE }, window.location.origin);
  }
}

function showRestoreSessionPrompt(loginUrl, onSuccess) {
  let popup = null;

  Modal.warning({
    content: "Your session has expired. Please login to continue.",
    okText: (
      <React.Fragment>
        Login <i className="fa m-r-5" aria-hidden="true" />
      </React.Fragment>
    ),
    centered: true,
    mask: true,
    maskClosable: false,
    keyboard: false,
    onOk: closeModal => {
      if (popup && !popup.closed) {
        popup.focus();
        return; // popup already shown
      }

      // Popup auth doesn't work with Stacklet login.
      window.location.href = loginUrl;
      /*
      popup = window.open(loginUrl, "Restore Session", map(popupOptions, (value, key) => `${key}=${value}`).join(","));

      const handlePostMessage = event => {
        if (event.data.type === SESSION_RESTORED_MESSAGE) {
          if (popup) {
            popup.close();
          }
          popup = null;
          window.removeEventListener("message", handlePostMessage);
          closeModal();
          onSuccess();
        }
      };

      window.addEventListener("message", handlePostMessage, false);
      */
    },
  });
}

let restoreSessionPromise = null;

export function restoreSession() {
  if (!restoreSessionPromise) {
    restoreSessionPromise = new Promise(resolve => {
      showRestoreSessionPrompt(Auth.getLoginUrl(), () => {
        restoreSessionPromise = null;
        resolve();
      });
    });
  }

  return restoreSessionPromise;
}
