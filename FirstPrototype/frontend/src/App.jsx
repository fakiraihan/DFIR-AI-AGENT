import React, { useEffect, useState, Suspense, lazy } from 'react'
import { Box, Toolbar, useMediaQuery, useTheme, CircularProgress, Typography } from '@mui/material'
import Header from './components/Header'
import Sidebar from './components/Sidebar'
import UploadPage from './components/UploadPage'

const InvestigationPage = lazy(() => import('./components/InvestigationPage'))
const SettingsPage = lazy(() => import('./components/SettingsPage'))

const STORAGE_KEYS = {
  currentView: 'dfir.currentView',
  sessionId: 'dfir.sessionId',
}

const VALID_VIEWS = new Set(['upload', 'investigation', 'settings'])

const getStoredWorkspaceState = () => {
  if (typeof window === 'undefined') {
    return {
      currentView: 'upload',
      sessionId: null,
    }
  }

  try {
    const storedSessionId = window.localStorage.getItem(STORAGE_KEYS.sessionId)
    const storedView = window.localStorage.getItem(STORAGE_KEYS.currentView)
    const sessionId = storedSessionId && storedSessionId.trim() ? storedSessionId : null
    const currentView = VALID_VIEWS.has(storedView) ? storedView : 'upload'

    return {
      sessionId,
      currentView: currentView === 'investigation' && !sessionId ? 'upload' : currentView,
    }
  } catch (error) {
    console.error('Failed to restore workspace state:', error)

    return {
      currentView: 'upload',
      sessionId: null,
    }
  }
}

const drawerWidth = 260;

function App() {
  const storedWorkspaceState = getStoredWorkspaceState()
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));
  const [currentView, setCurrentView] = useState(storedWorkspaceState.currentView) // upload, investigation, settings
  const [sessionId, setSessionId] = useState(storedWorkspaceState.sessionId)
  const [sidebarOpen, setSidebarOpen] = useState(!isMobile)
  const [appStarted, setAppStarted] = useState(() => storedWorkspaceState.currentView !== 'upload')

  const showShell = appStarted || currentView !== 'upload'

  // Sync sidebar open state when mobile state changes
  React.useEffect(() => {
    setSidebarOpen(!isMobile)
  }, [isMobile])

  useEffect(() => {
    if (typeof window === 'undefined') {
      return
    }

    try {
      if (sessionId) {
        window.localStorage.setItem(STORAGE_KEYS.sessionId, sessionId)
      } else {
        window.localStorage.removeItem(STORAGE_KEYS.sessionId)
      }
    } catch (error) {
      console.error('Failed to persist session id:', error)
    }
  }, [sessionId])

  useEffect(() => {
    if (typeof window === 'undefined') {
      return
    }

    const persistedView = currentView === 'investigation' && !sessionId ? 'upload' : currentView

    try {
      window.localStorage.setItem(STORAGE_KEYS.currentView, persistedView)
    } catch (error) {
      console.error('Failed to persist current view:', error)
    }
  }, [currentView, sessionId])

  const handleSetCurrentView = (view) => {
    const nextView = view === 'investigation' && !sessionId ? 'upload' : view

    setCurrentView(nextView)
    if (isMobile) {
      setSidebarOpen(false)
    }
  }

  const handleUploadSuccess = (newSessionId) => {
    setSessionId(newSessionId)
    setCurrentView('investigation')
  }

  const handleSelectSession = (selectedSessionId) => {
    setSessionId(selectedSessionId)
    setCurrentView('investigation')
    if (isMobile) {
      setSidebarOpen(false)
    }
  }

  const handleBackToUpload = () => {
    setCurrentView('upload')
    setSessionId(null)
  }

  const handleSessionDeleted = (deletedSessionId) => {
    if (deletedSessionId === sessionId) {
      handleBackToUpload()
    }
  }

  return (
    <Box sx={{ display: 'flex', minHeight: '100vh', width: '100%', bgcolor: 'background.default' }}>
      <Header 
        sidebarOpen={sidebarOpen}
        setSidebarOpen={setSidebarOpen}
        drawerWidth={drawerWidth}
        currentView={currentView}
        showShell={showShell}
      />
      
      <Sidebar 
        isOpen={showShell && sidebarOpen}
        setIsOpen={setSidebarOpen}
        currentView={currentView}
        setCurrentView={handleSetCurrentView}
        sessionId={sessionId}
        onSelectSession={handleSelectSession}
        onSessionDeleted={handleSessionDeleted}
        drawerWidth={drawerWidth}
        isMobile={isMobile}
      />

      <Box
        component="main"
        sx={{
          flexGrow: 1,
          p: 3,
          width: { xs: '100%', md: `calc(100% - ${showShell && sidebarOpen ? drawerWidth : 0}px)` },
          minHeight: '100vh',
          display: 'flex',
          flexDirection: 'column',
          transition: theme.transitions.create(['width', 'margin'], {
            easing: theme.transitions.easing.sharp,
            duration: theme.transitions.duration.leavingScreen,
          }),
          ...(showShell && sidebarOpen && !isMobile && {
            transition: theme.transitions.create(['width', 'margin'], {
              easing: theme.transitions.easing.easeOut,
              duration: theme.transitions.duration.enteringScreen,
            }),
          }),
        }}
      >
        {showShell && <Toolbar />} {/* Spacer for AppBar */}
        
        {currentView === 'upload' && (
          <UploadPage 
            onUploadSuccess={handleUploadSuccess} 
            onStart={() => setAppStarted(true)} 
            isLanding={!appStarted}
          />
        )}
        
        {currentView === 'investigation' && sessionId && (
          <Suspense fallback={
            <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', flexGrow: 1 }}>
              <CircularProgress size={60} thickness={4} sx={{ mb: 3 }} />
              <Typography variant="h6" color="text.secondary">Loading investigation module...</Typography>
            </Box>
          }>
            <InvestigationPage 
              sessionId={sessionId}
              onBackToUpload={handleBackToUpload}
              onSessionMissing={handleBackToUpload}
            />
          </Suspense>
        )}

        {currentView === 'settings' && (
          <Suspense fallback={
            <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', flexGrow: 1 }}>
              <CircularProgress size={60} thickness={4} sx={{ mb: 3 }} />
              <Typography variant="h6" color="text.secondary">Loading settings module...</Typography>
            </Box>
          }>
            <SettingsPage />
          </Suspense>
        )}
      </Box>
    </Box>
  )
}

export default App
