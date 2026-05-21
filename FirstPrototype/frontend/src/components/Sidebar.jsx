import React, { useEffect, useState } from 'react'
import axios from 'axios'
import { Drawer, List, ListItem, ListItemButton, ListItemIcon, ListItemText, Typography, Box, Divider, Toolbar, Chip, Stack, Button, CircularProgress, Tooltip, IconButton } from '@mui/material'
import UploadFileIcon from '@mui/icons-material/UploadFile'
import SearchIcon from '@mui/icons-material/Search'
import SettingsRoundedIcon from '@mui/icons-material/SettingsRounded'
import FolderOpenOutlinedIcon from '@mui/icons-material/FolderOpenOutlined'
import HistoryRoundedIcon from '@mui/icons-material/HistoryRounded'
import RefreshRoundedIcon from '@mui/icons-material/RefreshRounded'
import EditRoundedIcon from '@mui/icons-material/EditRounded'
import DeleteOutlineRoundedIcon from '@mui/icons-material/DeleteOutlineRounded'

const formatHistoryDate = (value) => {
  if (!value) return 'No timestamp'

  const parsedDate = new Date(value)
  return Number.isNaN(parsedDate.getTime()) ? 'No timestamp' : parsedDate.toLocaleString()
}

const getStatusColor = (status) => {
  if (status === 'completed') return 'success'
  if (status === 'error' || status === 'failed') return 'error'
  if (status === 'processing') return 'info'
  return 'default'
}

const Sidebar = ({ isOpen, setIsOpen, currentView, setCurrentView, sessionId, onSelectSession, onSessionDeleted, drawerWidth, isMobile }) => {
  const [sessions, setSessions] = useState([])
  const [historyLoading, setHistoryLoading] = useState(false)
  const [historyError, setHistoryError] = useState(null)

  const sessionDisplay = sessionId
    ? sessionId.length > 18
      ? `${sessionId.slice(0, 8)}...${sessionId.slice(-6)}`
      : sessionId
    : null

  const fetchSessions = async () => {
    setHistoryLoading(true)
    setHistoryError(null)

    try {
      const response = await axios.get('/api/sessions')
      setSessions(Array.isArray(response.data?.sessions) ? response.data.sessions : [])
    } catch (error) {
      console.error('Failed to fetch session history:', error)
      setHistoryError('History unavailable')
    } finally {
      setHistoryLoading(false)
    }
  }

  useEffect(() => {
    fetchSessions()
  }, [sessionId])

  const handleRenameSession = async (event, item) => {
    event.stopPropagation()

    const currentTitle = item.title || item.file_name || item.session_id
    const nextTitle = window.prompt('Rename session history:', currentTitle)
    if (nextTitle === null) return

    const trimmedTitle = nextTitle.trim()
    if (!trimmedTitle || trimmedTitle === currentTitle) return

    try {
      const response = await axios.patch(`/api/sessions/${item.session_id}`, { title: trimmedTitle })
      setSessions((currentSessions) => currentSessions.map((sessionItem) => (
        sessionItem.session_id === item.session_id ? response.data : sessionItem
      )))
    } catch (error) {
      console.error('Failed to rename session:', error)
      setHistoryError('Failed to rename session')
    }
  }

  const handleDeleteSession = async (event, item) => {
    event.stopPropagation()

    const title = item.title || item.file_name || item.session_id
    const confirmed = window.confirm(`Delete session "${title}"? Uploaded logs and saved reports for this session will also be removed.`)
    if (!confirmed) return

    try {
      await axios.delete(`/api/sessions/${item.session_id}`)
      setSessions((currentSessions) => currentSessions.filter((sessionItem) => sessionItem.session_id !== item.session_id))
      if (onSessionDeleted) {
        onSessionDeleted(item.session_id)
      }
    } catch (error) {
      console.error('Failed to delete session:', error)
      setHistoryError('Failed to delete session')
    }
  }

  const menuItems = [
    {
      id: 'upload',
      label: 'Upload Log',
      icon: <UploadFileIcon />,
      enabled: true
    },
    {
      id: 'investigation',
      label: 'Investigation',
      icon: <SearchIcon />,
      enabled: !!sessionId
    }
  ]

  const drawerContent = (
    <Box sx={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <Toolbar sx={{ pt: 2, pb: 1, alignItems: 'flex-start', minHeight: 'auto !important' }}>
         <Box sx={{ display: 'flex', flexDirection: 'column', width: '100%' }}>
            <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 0.5 }}>
              <SearchIcon sx={{ color: 'primary.main', fontSize: 24 }} />
              <Typography variant="h6" sx={{ fontWeight: 700, color: '#F8FAFC', letterSpacing: '-0.02em', lineHeight: 1.1 }}>
                DFIR <Box component="span" sx={{ color: 'primary.main' }}>Agent</Box>
              </Typography>
            </Stack>
            <Typography variant="caption" sx={{ color: 'text.secondary', fontWeight: 500, letterSpacing: '0.02em' }}>
              Cyber Incident Investigation
            </Typography>
         </Box>
      </Toolbar>
      <Divider sx={{ mt: 1, opacity: 0.5 }} />
      <Box sx={{ p: 2.5, flexGrow: 1 }}>
        <Box sx={{ px: 1.5, mb: 1.5 }}>
          <Typography variant="overline" color="text.secondary">
            Workspace
          </Typography>
        </Box>

        <List sx={{ mb: 2 }}>
          {menuItems.map(item => (
            <ListItem key={item.id} disablePadding>
              <ListItemButton
                selected={currentView === item.id}
                disabled={!item.enabled}
                onClick={() => {
                  if (item.enabled) setCurrentView(item.id)
                }}
              >
                <ListItemIcon sx={{ minWidth: 40, color: currentView === item.id ? 'primary.main' : 'inherit' }}>
                  {item.icon}
                </ListItemIcon>
                <ListItemText 
                  primary={item.label}
                  primaryTypographyProps={{ 
                    fontWeight: currentView === item.id ? 600 : 500,
                    fontSize: '0.95rem'
                  }}
                />
              </ListItemButton>
            </ListItem>
          ))}
        </List>

        {sessionId && (
          <>
            <Divider sx={{ my: 2, opacity: 0.5 }} />
            <Box sx={{ px: 1.5 }}>
              <Typography variant="overline" color="text.secondary">
                Active session
              </Typography>
              <Box
                sx={{
                  mt: 1,
                  p: 2,
                  borderRadius: 3,
                  bgcolor: 'rgba(6, 182, 212, 0.04)',
                  border: '1px solid',
                  borderColor: 'rgba(6, 182, 212, 0.2)',
                  boxShadow: 'inset 0 0 20px rgba(6, 182, 212, 0.02)',
                }}
              >
                <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1.5 }}>
                  <FolderOpenOutlinedIcon sx={{ fontSize: 18, color: 'primary.main' }} />
                  <Typography variant="subtitle2" sx={{ color: 'primary.light' }}>Current investigation</Typography>
                </Stack>
                <Chip label="In progress" size="small" sx={{ mb: 1.5, bgcolor: 'rgba(6, 182, 212, 0.1)', color: 'primary.light', border: '1px solid rgba(6, 182, 212, 0.3)' }} />
                <Typography variant="caption" color="text.secondary" display="block">
                  Session ID
                </Typography>
                <Typography variant="body2" sx={{ fontFamily: 'monospace', wordBreak: 'break-all', color: '#F8FAFC' }} title={sessionId}>
                  {sessionDisplay}
                </Typography>
              </Box>
            </Box>
          </>
        )}

        <Divider sx={{ my: 2 }} />
        <Box sx={{ px: 1.5 }}>
          <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ mb: 1 }}>
            <Stack direction="row" spacing={1} alignItems="center">
              <HistoryRoundedIcon sx={{ fontSize: 18, color: 'text.secondary' }} />
              <Typography variant="overline" color="text.secondary">
                History
              </Typography>
            </Stack>
            <Tooltip title="Refresh history">
              <span>
                <Button
                  size="small"
                  variant="text"
                  onClick={fetchSessions}
                  disabled={historyLoading}
                  sx={{ minWidth: 0, px: 0.75 }}
                >
                  {historyLoading ? <CircularProgress size={16} /> : <RefreshRoundedIcon fontSize="small" />}
                </Button>
              </span>
            </Tooltip>
          </Stack>

          {historyError && (
            <Typography variant="caption" color="error" display="block" sx={{ mb: 1 }}>
              {historyError}
            </Typography>
          )}

          {!historyLoading && sessions.length === 0 && !historyError && (
            <Typography variant="caption" color="text.secondary" display="block" sx={{ px: 0.5 }}>
              No previous sessions yet.
            </Typography>
          )}

          <List disablePadding sx={{ maxHeight: 300, overflowY: 'auto', pr: 0.5 }}>
            {sessions.map((item) => {
              const selected = item.session_id === sessionId
              const title = item.title || item.file_name || item.session_id
              const subtitle = formatHistoryDate(item.completion_time || item.last_update || item.upload_time)

              return (
                <ListItem key={item.session_id} disablePadding sx={{ mb: 0.75 }}>
                  <ListItemButton
                    selected={selected}
                    onClick={() => onSelectSession(item.session_id)}
                    sx={{
                      alignItems: 'flex-start',
                      borderRadius: 2,
                      border: '1px solid',
                      borderColor: selected ? 'primary.main' : 'divider',
                      bgcolor: selected ? 'rgba(6, 182, 212, 0.08)' : 'transparent',
                    }}
                  >
                    <ListItemText
                      primary={title}
                      secondary={subtitle}
                      primaryTypographyProps={{
                        fontSize: '0.84rem',
                        fontWeight: selected ? 700 : 600,
                        noWrap: true,
                        title,
                      }}
                      secondaryTypographyProps={{
                        fontSize: '0.72rem',
                        color: 'text.secondary',
                      }}
                    />
                    <Stack direction="column" spacing={0.5} alignItems="flex-end" sx={{ ml: 1 }}>
                      <Chip
                        label={item.status || 'pending'}
                        color={getStatusColor(item.status)}
                        size="small"
                        variant="outlined"
                        sx={{ height: 22, fontSize: '0.68rem' }}
                      />
                      <Stack direction="row" spacing={0.25}>
                        <Tooltip title="Rename session">
                          <IconButton
                            size="small"
                            onClick={(event) => handleRenameSession(event, item)}
                            sx={{ p: 0.25 }}
                          >
                            <EditRoundedIcon sx={{ fontSize: 16 }} />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Delete session and saved files">
                          <IconButton
                            size="small"
                            color="error"
                            onClick={(event) => handleDeleteSession(event, item)}
                            sx={{ p: 0.25 }}
                          >
                            <DeleteOutlineRoundedIcon sx={{ fontSize: 16 }} />
                          </IconButton>
                        </Tooltip>
                      </Stack>
                    </Stack>
                  </ListItemButton>
                </ListItem>
              )
            })}
          </List>
        </Box>
      </Box>
      
      <Box sx={{ borderTop: '1px solid', borderColor: 'divider' }}>
        <Box sx={{ p: 2.5, pb: 1 }}>
          <List disablePadding>
            <ListItem disablePadding>
              <ListItemButton
                selected={currentView === 'settings'}
                onClick={() => setCurrentView('settings')}
              >
                <ListItemIcon sx={{ minWidth: 40, color: currentView === 'settings' ? 'primary.main' : 'inherit' }}>
                  <SettingsRoundedIcon />
                </ListItemIcon>
                <ListItemText 
                  primary="Settings"
                  primaryTypographyProps={{ 
                    fontWeight: currentView === 'settings' ? 600 : 500,
                    fontSize: '0.95rem'
                  }}
                />
              </ListItemButton>
            </ListItem>
          </List>
        </Box>
        <Box sx={{ px: 3, pb: 3 }}>
          <Typography variant="caption" color="text.secondary" display="block">
            v1.0.0
          </Typography>
          <Typography variant="caption" color="text.secondary" display="block">
            © 2026 Poltek SSN
          </Typography>
        </Box>
      </Box>
    </Box>
  )

  return (
    <Box 
      component="nav" 
      sx={{ 
        width: { md: isOpen ? drawerWidth : 0 }, 
        flexShrink: { md: 0 },
        transition: 'width 225ms cubic-bezier(0.4, 0, 0.6, 1) 0ms'
      }}
    >
      {isMobile ? (
        <Drawer
          variant="temporary"
          open={isOpen}
          onClose={() => setIsOpen(false)}
          ModalProps={{
            keepMounted: true, // Better open performance on mobile.
          }}
          sx={{
            display: { xs: 'block', md: 'none' },
            '& .MuiDrawer-paper': { boxSizing: 'border-box', width: drawerWidth },
          }}
        >
          {drawerContent}
        </Drawer>
      ) : (
        <Drawer
          variant="persistent"
          open={isOpen}
          sx={{
            display: { xs: 'none', md: 'block' },
            '& .MuiDrawer-paper': { boxSizing: 'border-box', width: drawerWidth },
          }}
        >
          {drawerContent}
        </Drawer>
      )}
    </Box>
  )
}

export default Sidebar
