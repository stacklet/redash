import React, { useMemo, useCallback, useState, useRef } from "react";
import ReactDOM from "react-dom";
import PropTypes from "prop-types";
import { first, includes } from "lodash";
import AppstoreOutlined from "@ant-design/icons/AppstoreOutlined";
import FileSearchOutlined from "@ant-design/icons/FileSearchOutlined";
import WarningOutlined from "@ant-design/icons/WarningOutlined";
import PlusOutlined from "@ant-design/icons/PlusOutlined";
import QuestionCircleOutlined from "@ant-design/icons/QuestionCircleOutlined";
import SettingOutlined from "@ant-design/icons/SettingOutlined";
import UpOutlined from "@ant-design/icons/UpOutlined";
import DownOutlined from "@ant-design/icons/DownOutlined";
import UserOutlined from "@ant-design/icons/UserOutlined";
import CreateDashboardDialog from "@/components/dashboards/CreateDashboardDialog";
import { useCurrentRoute } from "@/components/ApplicationArea/Router";
import { Auth, currentUser, clientConfig } from "@/services/auth";
import settingsMenu from "@/services/settingsMenu";
import navigateTo from "@/components/ApplicationArea/navigateTo";
import classnames from "classnames";
import AppSwitcher from "./AppSwitcher";
import frontendVersion from "@/version.json";

import "./StackletSidebar.less";

// Stacklet Logo Component
function StackletLogo({ className }) {
  return (
    <svg
      className={className}
      width="28"
      height="28"
      viewBox="0 0 23 24"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      title="stacklet">
      <path
        d="M11.3087 0L0.785645 7.00555V7.08568V10.3332V10.4133L2.56711 11.5994L0.785645 12.7851V12.8653V16.1929L11.3087 23.1984V23.1989L21.8322 16.1933V16.1132V12.8657V12.7856L20.0507 11.5994L21.8322 10.4138V10.3336V7.08611V7.00599L11.3087 0ZM19.393 14.4892L17.5515 15.7148L11.3087 19.8708L3.2248 14.4892L5.06634 13.2637L11.3087 17.4193L15.0523 14.9271V11.5999L17.5515 13.2633V13.2637L19.393 14.4892ZM17.5515 9.93518L11.3087 5.77958L6.90787 8.70921L9.4071 10.373L11.3087 9.10722L15.0518 11.599L11.3087 14.0912L7.56556 11.5994V11.599L5.06634 9.93518L3.2248 8.70921L5.06634 7.48324L11.3087 3.32764L19.393 8.70921L17.5515 9.93518Z"
        fill="currentColor"
      />
    </svg>
  );
}

StackletLogo.propTypes = {
  className: PropTypes.string,
};

function useNavbarActiveState() {
  const currentRoute = useCurrentRoute();

  return useMemo(
    () => ({
      dashboards: includes(
        [
          "Dashboards.List",
          "Dashboards.Favorites",
          "Dashboards.My",
          "Dashboards.ViewOrEdit",
          "Dashboards.LegacyViewOrEdit",
        ],
        currentRoute.id
      ),
      queries: includes(
        [
          "Queries.List",
          "Queries.Favorites",
          "Queries.Archived",
          "Queries.My",
          "Queries.View",
          "Queries.New",
          "Queries.Edit",
        ],
        currentRoute.id
      ),
      alerts: includes(["Alerts.List", "Alerts.New", "Alerts.View", "Alerts.Edit"], currentRoute.id),
      settings: includes(["DataSources.List"], currentRoute.id),
    }),
    [currentRoute.id]
  );
}

export default function StackletSidebar() {
  const firstSettingsTab = first(settingsMenu.getAvailableItems());
  const activeState = useNavbarActiveState();

  const canCreateQuery = currentUser.hasPermission("create_query");
  const canCreateDashboard = currentUser.hasPermission("create_dashboard");
  const canCreateAlert = currentUser.hasPermission("list_alerts");

  // Build navigation items
  const navItems = useMemo(() => {
    const items = [];

    // Dashboards
    if (currentUser.hasPermission("list_dashboards")) {
      items.push({
        id: "dashboards",
        label: "Dashboards",
        target: "/dashboards",
        Icon: AppstoreOutlined,
        active: activeState.dashboards,
      });
    }

    // Queries
    if (currentUser.hasPermission("view_query")) {
      items.push({
        id: "queries",
        label: "Queries",
        target: "/queries",
        Icon: FileSearchOutlined,
        active: activeState.queries,
      });
    }

    // Alerts
    if (currentUser.hasPermission("list_alerts")) {
      items.push({
        id: "alerts",
        label: "Alerts",
        target: "/alerts",
        Icon: WarningOutlined,
        active: activeState.alerts,
      });
    }

    // Create menu as an accordion (branch node)
    if (canCreateQuery || canCreateDashboard || canCreateAlert) {
      const createChildren = [];

      if (canCreateQuery) {
        createChildren.push({
          id: "new-query",
          label: "New Query",
          target: "/queries/new",
        });
      }

      if (canCreateDashboard) {
        createChildren.push({
          id: "new-dashboard",
          label: "New Dashboard",
          target: "#new-dashboard", // Special target to trigger dialog
        });
      }

      if (canCreateAlert) {
        createChildren.push({
          id: "new-alert",
          label: "New Alert",
          target: "/alerts/new",
        });
      }

      items.push({
        id: "create",
        label: "Create",
        Icon: PlusOutlined,
        children: createChildren,
      });
    }

    // Help
    items.push({
      id: "help",
      label: "Help",
      target: "#help", // Special target to trigger help drawer
      Icon: QuestionCircleOutlined,
    });

    // Settings
    if (firstSettingsTab) {
      items.push({
        id: "settings",
        label: "Settings",
        target: firstSettingsTab.path,
        Icon: SettingOutlined,
        active: activeState.settings,
      });
    }

    return items;
  }, [canCreateQuery, canCreateDashboard, canCreateAlert, firstSettingsTab, activeState]);

  // Handle navigation
  const handleNavigate = useCallback(to => {
    // Handle special cases
    if (to === "#new-dashboard") {
      CreateDashboardDialog.showModal();
      return;
    }

    if (to === "#help") {
      // Open help in new window
      window.open("https://redash.io/help", "_blank");
      return;
    }

    // Regular navigation
    navigateTo(to);
  }, []);

  return (
    <div className="stacklet-sidebar-wrapper">
      <Sidebar navItems={navItems} navigate={handleNavigate} />
    </div>
  );
}

// User Menu Component
function UserMenu() {
  const [isOpen, setIsOpen] = useState(false);
  const triggerRef = useRef(null);
  const [dropdownPosition, setDropdownPosition] = useState({ top: 0, left: 0 });

  const updateDropdownPosition = useCallback(() => {
    if (triggerRef.current) {
      const rect = triggerRef.current.getBoundingClientRect();
      setDropdownPosition({
        top: rect.top - 8,
        left: rect.right + 8,
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

  const handleLogout = useCallback(() => {
    Auth.logout();
  }, []);

  const handleNavigate = useCallback(
    to => {
      navigateTo(to);
      handleClose();
    },
    [handleClose]
  );

  const version = clientConfig.version || "Unknown";
  const frontendVersionShort = frontendVersion ? frontendVersion.substring(0, 8) : "";
  const showFrontendVersion = frontendVersion && frontendVersion !== clientConfig.version;

  const dropdown = isOpen ? (
    <>
      <div
        className="user-menu-backdrop"
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
        className="user-menu-dropdown"
        style={{
          position: "fixed",
          top: `${dropdownPosition.top}px`,
          left: `${dropdownPosition.left}px`,
          transform: "translateY(-100%)",
          display: "flex",
          flexDirection: "column",
          width: "280px",
          background: "rgb(26, 26, 26)",
          border: "1px solid #424B54",
          borderRadius: "8px",
          zIndex: 1101,
          boxShadow: "0 4px 12px rgba(0, 0, 0, 0.3)",
          overflow: "hidden",
        }}>
        <div
          style={{
            borderBottom: "1px solid #424B54",
            padding: "12px 16px",
          }}>
          <div style={{ fontSize: "12px", color: "#9CA3AF", marginBottom: "4px" }}>Signed in as</div>
          <div style={{ fontSize: "14px", fontWeight: 600, color: "white" }}>{currentUser.email}</div>
        </div>
        <div style={{ display: "flex", flexDirection: "column" }}>
          <button
            className="user-menu-item"
            onClick={() => handleNavigate("/users/me")}
            style={{
              display: "flex",
              alignItems: "center",
              width: "100%",
              padding: "12px 16px",
              margin: 0,
              background: "transparent",
              color: "#D3D5D7",
              cursor: "pointer",
              fontSize: "14px",
              textAlign: "left",
              border: "none",
            }}>
            Profile
          </button>
          {currentUser.hasPermission("super_admin") && (
            <button
              className="user-menu-item"
              onClick={() => handleNavigate("/admin/status")}
              style={{
                display: "flex",
                alignItems: "center",
                width: "100%",
                padding: "12px 16px",
                margin: 0,
                background: "transparent",
                color: "#D3D5D7",
                cursor: "pointer",
                fontSize: "14px",
                textAlign: "left",
                border: "none",
              }}>
              System Status
            </button>
          )}
          <div style={{ height: "1px", background: "#424B54", margin: "4px 0" }} />
          <button
            className="user-menu-item"
            onClick={handleLogout}
            style={{
              display: "flex",
              alignItems: "center",
              width: "100%",
              padding: "12px 16px",
              margin: 0,
              background: "transparent",
              color: "#D3D5D7",
              cursor: "pointer",
              fontSize: "14px",
              textAlign: "left",
              border: "none",
            }}>
            Sign Out
          </button>
          <div style={{ height: "1px", background: "#424B54", margin: "4px 0" }} />
          <div
            style={{
              padding: "12px 16px",
              fontSize: "12px",
              color: "#6B7280",
            }}>
            Version: {version}
            {showFrontendVersion && ` (${frontendVersionShort})`}
          </div>
        </div>
      </div>
    </>
  ) : null;

  return (
    <div className="user-menu">
      <button
        ref={triggerRef}
        className="user-menu-trigger"
        onClick={toggleOpen}
        aria-label="User menu"
        style={{
          display: "flex",
          alignItems: "center",
          gap: "12px",
          width: "100%",
          padding: "12px 16px",
          background: "transparent",
          border: "none",
          color: "white",
          cursor: "pointer",
          borderRadius: "4px",
          transition: "background-color 0.2s",
        }}>
        <div
          style={{
            width: "32px",
            height: "32px",
            borderRadius: "50%",
            overflow: "hidden",
            flexShrink: 0,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            background: "#374151",
          }}>
          {currentUser.profile_image_url ? (
            <img
              src={currentUser.profile_image_url}
              alt={currentUser.name}
              style={{ width: "100%", height: "100%", objectFit: "cover" }}
            />
          ) : (
            <UserOutlined style={{ fontSize: "18px", color: "#9CA3AF" }} />
          )}
        </div>
        <div style={{ flex: 1, textAlign: "left", overflow: "hidden" }}>
          <div
            style={{
              fontSize: "14px",
              fontWeight: 600,
              color: "white",
              whiteSpace: "nowrap",
              overflow: "hidden",
              textOverflow: "ellipsis",
            }}>
            {currentUser.name}
          </div>
        </div>
      </button>

      {isOpen && ReactDOM.createPortal(dropdown, document.body)}
    </div>
  );
}

// Custom Sidebar Component
// Todo: replace with Sidebar component from @stacklet-ui once redash is upgraded to react v18+
function Sidebar({ navItems, navigate }) {
  const [expandedItems, setExpandedItems] = useState({});

  const toggleExpanded = useCallback(itemId => {
    setExpandedItems(prev => ({
      ...prev,
      [itemId]: !prev[itemId],
    }));
  }, []);

  const handleItemClick = useCallback(
    item => {
      if (item.children) {
        toggleExpanded(item.id);
      } else if (item.target) {
        navigate(item.target);
      }
    },
    [navigate, toggleExpanded]
  );

  return (
    <div className="stacklet-sidebar">
      <div className="sidebar-header">
        <div className="sidebar-logo">
          <StackletLogo className="logo-svg" />
        </div>
        <div className="sidebar-app-switcher">
          <AppSwitcher />
        </div>
      </div>

      <nav className="sidebar-nav">
        {navItems.map(item => {
          const isExpanded = item.children && expandedItems[item.id];

          return (
            <div key={item.id} className="sidebar-item-wrapper">
              <button
                className={classnames("sidebar-item", {
                  active: item.active,
                  "has-children": item.children,
                  expanded: expandedItems[item.id],
                })}
                onClick={() => handleItemClick(item)}
                aria-label={item.label}>
                <span className="sidebar-item-icon">
                  <item.Icon />
                </span>

                <span className="sidebar-item-label">{item.label}</span>
                {item.children ? (
                  <span className="sidebar-item-arrow">
                    {expandedItems[item.id] ? <UpOutlined /> : <DownOutlined />}
                  </span>
                ) : null}
              </button>

              {isExpanded ? (
                <div className="sidebar-submenu">
                  {item.children.map(child => (
                    <button key={child.id} className="sidebar-submenu-item" onClick={() => navigate(child.target)}>
                      {child.label}
                    </button>
                  ))}
                </div>
              ) : null}
            </div>
          );
        })}
      </nav>

      <div className="sidebar-footer">
        <UserMenu />
      </div>
    </div>
  );
}

Sidebar.propTypes = {
  navItems: PropTypes.arrayOf(
    PropTypes.shape({
      id: PropTypes.string.isRequired,
      label: PropTypes.string.isRequired,
      target: PropTypes.string,
      Icon: PropTypes.elementType.isRequired,
      active: PropTypes.bool,
      children: PropTypes.arrayOf(
        PropTypes.shape({
          id: PropTypes.string.isRequired,
          label: PropTypes.string.isRequired,
          target: PropTypes.string.isRequired,
        })
      ),
    })
  ).isRequired,
  navigate: PropTypes.func.isRequired,
};
