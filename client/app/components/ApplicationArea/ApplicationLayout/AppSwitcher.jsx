import React, { useState, useCallback, useEffect, useRef } from "react";
import ReactDOM from "react-dom";
import AppstoreOutlined from "@ant-design/icons/AppstoreOutlined";
import classnames from "classnames";

import "./AppSwitcher.less";

async function fetchStackletConfig() {
  try {
    const response = await fetch("/stacklet/config");
    if (!response.ok) {
      throw new Error("Failed to fetch stacklet config");
    }
    return await response.json();
  } catch (error) {
    console.error("Error fetching stacklet config:", error);
    return null;
  }
}
// Custom Sidebar Component
// TODO: replace with AppSwitchercomponent from @stacklet-ui once redash is upgraded to react v18+
export default function AppSwitcher() {
  const [isOpen, setIsOpen] = useState(false);
  const [appOptions, setAppOptions] = useState([
    {
      label: "AssetDB",
      href: "", // Current app
      isCurrentApp: true,
    },
  ]);
  const triggerRef = useRef(null);
  const [dropdownPosition, setDropdownPosition] = useState({ top: 0, left: 0 });

  useEffect(() => {
    let isAbandoned = false;
    const isValidUrl = value => value && typeof value === "string" && value.trim();

    fetchStackletConfig().then(config => {
      if (isAbandoned) return;

      if (config) {
        const options = [
          {
            label: "AssetDB",
            href: "", // Current app
            isCurrentApp: true,
          },
        ];

        const appConfigs = [
          { key: "console", label: "Console" },
          { key: "jun0", label: "Jun0" },
          { key: "sinistral", label: "IaC Governance" },
        ];

        appConfigs.forEach(({ key, label }) => {
          if (isValidUrl(config[key])) {
            options.push({
              label,
              href: config[key],
              isCurrentApp: false,
            });
          }
        });

        setAppOptions(options);
      }
    });

    return () => {
      isAbandoned = true;
    };
  }, []);

  const updateDropdownPosition = useCallback(() => {
    if (triggerRef.current) {
      const rect = triggerRef.current.getBoundingClientRect();
      setDropdownPosition({
        top: rect.bottom + 8,
        left: rect.left,
      });
    }
  }, []);

  const toggleOpen = useCallback(() => {
    setIsOpen(prev => {
      if (!prev) {
        updateDropdownPosition();
      }
      return !prev;
    });
  }, [updateDropdownPosition]);

  const handleClose = useCallback(() => {
    setIsOpen(false);
  }, []);

  const handleAppClick = useCallback(
    href => {
      if (href) {
        window.location.href = href;
      }
      handleClose();
    },
    [handleClose]
  );

  // Get current app label
  const currentApp = appOptions.find(app => app.isCurrentApp);
  const currentAppLabel = currentApp ? currentApp.label : "AssetDB";

  // If there's only one app (AssetDB), don't show the switcher
  if (appOptions.length === 1) {
    return null;
  }

  const dropdown = isOpen ? (
    <>
      <div
        className="app-switcher-backdrop"
        onClick={handleClose}
        style={{
          position: "fixed",
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          zIndex: 1100,
          background: "transparent",
        }}
      />
      <div
        className="app-switcher-dropdown"
        style={{
          position: "fixed",
          top: `${dropdownPosition.top}px`,
          left: `${dropdownPosition.left}px`,
          display: "flex",
          flexDirection: "column",
          width: "229px",
          background: "rgb(26, 26, 26)", // Match sidebar background exactly
          border: "1px solid #424B54", // navy.L20
          borderRadius: "8px",
          zIndex: 1101,
          boxShadow: "0 4px 12px rgba(0, 0, 0, 0.3)",
        }}>
        <div
          style={{
            borderBottom: "1px solid #6E6E6E", // neutrals.stormyGray
            padding: "8px 32px",
          }}>
          <div style={{ fontSize: "14px", fontWeight: 600, color: "white" }}>Apps</div>
        </div>
        <div
          className="app-switcher-list"
          style={{
            display: "flex",
            flexDirection: "column",
            margin: 0,
            padding: 0,
            listStyle: "none",
          }}>
          {appOptions.map(app => (
            <a
              key={app.label}
              href={app.href || undefined}
              onClick={e => {
                e.preventDefault();
                if (!app.isCurrentApp) {
                  handleAppClick(app.href);
                }
              }}
              style={{
                display: "flex",
                alignItems: "center",
                width: "100%",
                padding: "12px 32px",
                margin: 0,
                background: app.isCurrentApp ? "#143644" : "transparent", // cobalt.D50
                color: "#D3D5D7", // navy.L80
                cursor: app.isCurrentApp ? "default" : "pointer",
                fontSize: "14px",
                textDecoration: "none",
                lineHeight: "1",
              }}
              onMouseEnter={e => {
                if (!app.isCurrentApp) {
                  e.currentTarget.style.background = "#143644"; // cobalt.D50
                }
              }}
              onMouseLeave={e => {
                if (!app.isCurrentApp) {
                  e.currentTarget.style.background = "transparent";
                }
              }}>
              {app.label}
            </a>
          ))}
        </div>
      </div>
    </>
  ) : null;

  return (
    <div className="app-switcher">
      <button
        ref={triggerRef}
        className={classnames("app-switcher-trigger", { open: isOpen })}
        onClick={toggleOpen}
        aria-label="Switch application">
        <span className="app-switcher-label">{currentAppLabel}</span>
        <AppstoreOutlined className="app-switcher-icon" />
      </button>

      {isOpen && ReactDOM.createPortal(dropdown, document.body)}
    </div>
  );
}
