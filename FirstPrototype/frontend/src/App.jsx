import React, { useEffect, useState, Suspense, lazy } from "react";
import {
  Box,
  Toolbar,
  useMediaQuery,
  useTheme,
  CircularProgress,
  Typography,
} from "@mui/material";
import Header from "./components/Header";
import Sidebar from "./components/Sidebar";
import UploadPage from "./components/UploadPage";
import AuthGate from "./components/AuthGate";
import HeroLanding from "./components/HeroLanding";

const InvestigationPage = lazy(() => import("./components/InvestigationPage"));
const SettingsPage = lazy(() => import("./components/SettingsPage"));

const STORAGE_KEYS = {
  currentView: "dfir.currentView",
  sessionId: "dfir.sessionId",
};

const VALID_VIEWS = new Set(["upload", "auth", "investigation", "settings"]);

const getStoredWorkspaceState = () => {
  if (typeof window === "undefined") {
    return {
      currentView: "upload",
      sessionId: null,
    };
  }

  try {
    const storedSessionId = window.localStorage.getItem(STORAGE_KEYS.sessionId);
    const storedView = window.localStorage.getItem(STORAGE_KEYS.currentView);
    const sessionId =
      storedSessionId && storedSessionId.trim() ? storedSessionId : null;
    const currentView = VALID_VIEWS.has(storedView) ? storedView : "upload";
    const restoredView = currentView === "auth" ? "upload" : currentView;

    return {
      sessionId,
      currentView:
        restoredView === "investigation" && !sessionId ? "upload" : restoredView,
    };
  } catch (error) {
    console.error("Failed to restore workspace state:", error);

    return {
      currentView: "upload",
      sessionId: null,
    };
  }
};

const drawerWidth = 260;

function App() {
  const storedWorkspaceState = getStoredWorkspaceState();
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));
  const [currentView, setCurrentView] = useState(
    storedWorkspaceState.currentView,
  ); // upload, investigation
  const [sessionId, setSessionId] = useState(storedWorkspaceState.sessionId);
  const [sidebarOpen, setSidebarOpen] = useState(!isMobile);
  const [appStarted, setAppStarted] = useState(
    () => storedWorkspaceState.currentView !== "upload",
  );
  const [currentUser, setCurrentUser] = useState(null);
  const [authLoading, setAuthLoading] = useState(true);

  const isAuthPage = currentView === "auth";
  const isLandingPage = !appStarted && currentView === "upload";
  const showShell = appStarted && !isAuthPage;

  // Sync sidebar open state when mobile state changes
  React.useEffect(() => {
    setSidebarOpen(!isMobile);
  }, [isMobile]);

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }

    try {
      if (sessionId) {
        window.localStorage.setItem(STORAGE_KEYS.sessionId, sessionId);
      } else {
        window.localStorage.removeItem(STORAGE_KEYS.sessionId);
      }
    } catch (error) {
      console.error("Failed to persist session id:", error);
    }
  }, [sessionId]);

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }

    const persistedView =
      currentView === "investigation" && !sessionId ? "upload" : currentView === "auth" ? "upload" : currentView;

    try {
      window.localStorage.setItem(STORAGE_KEYS.currentView, persistedView);
    } catch (error) {
      console.error("Failed to persist current view:", error);
    }
  }, [currentView, sessionId]);

  useEffect(() => {
    let active = true;

    const fetchCurrentUser = async () => {
      try {
        const response = await fetch("/api/auth/me");
        if (!active) return;
        if (response.ok) {
          const payload = await response.json();
          setCurrentUser(payload.user);
          if (storedWorkspaceState.currentView === "auth") {
            setCurrentView("upload");
            setAppStarted(true);
          }
        } else {
          setCurrentUser(null);
          if (
            ["investigation", "settings"].includes(
              storedWorkspaceState.currentView,
            )
          ) {
            setCurrentView("auth");
            setSessionId(null);
            setAppStarted(true);
          }
        }
      } catch (error) {
        console.error("Failed to fetch current user:", error);
        if (active) setCurrentUser(null);
      } finally {
        if (active) setAuthLoading(false);
      }
    };

    fetchCurrentUser();

    return () => {
      active = false;
    };
  }, []);

  const handleSetCurrentView = (view) => {
    let nextView = view === "investigation" && !sessionId ? "upload" : view;
    if (nextView === "upload" && !currentUser) {
      nextView = "auth";
    }

    setCurrentView(nextView);
    if (isMobile) {
      setSidebarOpen(false);
    }
  };

  const handleStart = () => {
    setAppStarted(true);
    setCurrentView(currentUser ? "upload" : "auth");
  };

  const handleAuthenticated = (user) => {
    setCurrentUser(user);
    setAppStarted(true);
    setCurrentView("upload");
  };

  const handleLogout = async () => {
    try {
      await fetch("/api/auth/logout", { method: "POST" });
    } catch (error) {
      console.error("Failed to logout:", error);
    }
    setCurrentUser(null);
    setSessionId(null);
    setCurrentView("auth");
    setAppStarted(true);
  };

  const handleUploadSuccess = (newSessionId) => {
    setSessionId(newSessionId);
    setCurrentView("investigation");
  };

  const handleSelectSession = (selectedSessionId) => {
    setSessionId(selectedSessionId);
    setCurrentView("investigation");
    if (isMobile) {
      setSidebarOpen(false);
    }
  };

  const handleBackToUpload = () => {
    setCurrentView("upload");
    setSessionId(null);
  };

  const handleSessionDeleted = (deletedSessionId) => {
    if (deletedSessionId === sessionId) {
      handleBackToUpload();
    }
  };

  return (
    <Box
      sx={{
        display: "flex",
        minHeight: "100vh",
        width: "100%",
        bgcolor: "background.default",
      }}
    >
      {showShell && (
        <>
          <Header
            sidebarOpen={sidebarOpen}
            setSidebarOpen={setSidebarOpen}
            showShell={showShell}
          />

          <Sidebar
            isOpen={sidebarOpen}
            setIsOpen={setSidebarOpen}
            currentView={currentView}
            setCurrentView={handleSetCurrentView}
            sessionId={sessionId}
            onSelectSession={handleSelectSession}
            onSessionDeleted={handleSessionDeleted}
            drawerWidth={drawerWidth}
            isMobile={isMobile}
            currentUser={currentUser}
            onLogout={handleLogout}
          />
        </>
      )}

      <Box
        component="main"
        sx={{
          flexGrow: 1,
          p: showShell ? 3 : 0,
          width: {
            xs: "100%",
            md: `calc(100% - ${showShell && sidebarOpen ? drawerWidth : 0}px)`,
          },
          minHeight: "100vh",
          display: "flex",
          flexDirection: "column",
          ...(isAuthPage && {
            p: 0,
            width: "100%",
            alignItems: "center",
            justifyContent: "center",
          }),
        }}
      >
        {showShell && <Toolbar />} {/* Spacer for AppBar */}
        {isLandingPage && (
          <HeroLanding onStart={handleStart} />
        )}
        {authLoading && showShell && (
          <Box
            sx={{
              display: "flex",
              flexDirection: "column",
              alignItems: "center",
              justifyContent: "center",
              flexGrow: 1,
            }}
          >
            <CircularProgress size={52} thickness={4} sx={{ mb: 2 }} />
            <Typography variant="body1" color="text.secondary">
              Checking account session...
            </Typography>
          </Box>
        )}
        {authLoading && isAuthPage && (
          <Box
            sx={{
              display: "flex",
              flexDirection: "column",
              alignItems: "center",
              justifyContent: "center",
              minHeight: "100vh",
            }}
          >
            <CircularProgress size={52} thickness={4} sx={{ mb: 2 }} />
            <Typography variant="body1" color="text.secondary">
              Checking account session...
            </Typography>
          </Box>
        )}
        {!authLoading && currentView === "auth" && (
          <AuthGate onAuthenticated={handleAuthenticated} />
        )}
        {appStarted && currentView === "upload" && !authLoading && (
          <UploadPage
            onUploadSuccess={handleUploadSuccess}
            currentUser={currentUser}
          />
        )}
        {!authLoading && currentView === "settings" && (
          <Suspense
            fallback={
              <Box
                sx={{
                  display: "flex",
                  flexDirection: "column",
                  alignItems: "center",
                  justifyContent: "center",
                  flexGrow: 1,
                }}
              >
                <CircularProgress size={52} thickness={4} sx={{ mb: 2 }} />
                <Typography variant="body1" color="text.secondary">
                  Loading settings...
                </Typography>
              </Box>
            }
          >
            <SettingsPage />
          </Suspense>
        )}
        {!authLoading && currentView === "investigation" && sessionId && (
          <Suspense
            fallback={
              <Box
                sx={{
                  display: "flex",
                  flexDirection: "column",
                  alignItems: "center",
                  justifyContent: "center",
                  flexGrow: 1,
                }}
              >
                <CircularProgress size={60} thickness={4} sx={{ mb: 3 }} />
                <Typography variant="h6" color="text.secondary">
                  Loading investigation module...
                </Typography>
              </Box>
            }
          >
            <InvestigationPage
              sessionId={sessionId}
              onBackToUpload={handleBackToUpload}
              onSessionMissing={handleBackToUpload}
            />
          </Suspense>
        )}
      </Box>
    </Box>
  );
}

export default App;
