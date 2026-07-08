import React, { useEffect, useState } from 'react'
import axios from 'axios'
import { Drawer, List, ListItem, ListItemButton, ListItemIcon, ListItemText, Typography, Box, Divider, Toolbar, Stack, Button, CircularProgress, Tooltip, IconButton, Menu, MenuItem } from '@mui/material'
import UploadFileIcon from '@mui/icons-material/UploadFile'
import SearchIcon from '@mui/icons-material/Search'
import HistoryRoundedIcon from '@mui/icons-material/HistoryRounded'
import RefreshRoundedIcon from '@mui/icons-material/RefreshRounded'
import EditRoundedIcon from '@mui/icons-material/EditRounded'
import DeleteOutlineRoundedIcon from '@mui/icons-material/DeleteOutlineRounded'
import AccountCircleRoundedIcon from '@mui/icons-material/AccountCircleRounded'
import LogoutRoundedIcon from '@mui/icons-material/LogoutRounded'
import SettingsRoundedIcon from '@mui/icons-material/SettingsRounded'

const Sidebar = ({ isOpen, setIsOpen, currentView, setCurrentView, sessionId, onSelectSession, onSessionDeleted, drawerWidth, isMobile, currentUser, onLogout }) => {
  const [sessions, setSessions] = useState([])
  const [historyLoading, setHistoryLoading] = useState(false)
  const [historyError, setHistoryError] = useState(null)
  const [profileMenuAnchor, setProfileMenuAnchor] = useState(null)
  const profileMenuOpen = Boolean(profileMenuAnchor)

  const fetchSessions = async () => {
    if (!currentUser) {
      setSessions([])
      setHistoryError(null)
      return
    }

    setHistoryLoading(true)
    setHistoryError(null)

    try {
      const response = await axios.get('/api/sessions')
      setSessions(Array.isArray(response.data?.sessions) ? response.data.sessions : [])
    } catch (error) {
      console.error('Failed to fetch sessions:', error)
      setHistoryError('Sessions unavailable')
    } finally {
      setHistoryLoading(false)
    }
  }

  useEffect(() => {
    fetchSessions()
  }, [sessionId, currentUser?.id])

  const handleRenameSession = async (event, item) => {
    event.stopPropagation()

    const currentTitle = item.title || item.file_name || item.session_id
    const nextTitle = window.prompt('Rename session:', currentTitle)
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

  const handleOpenProfileMenu = (event) => {
    setProfileMenuAnchor(event.currentTarget)
  }

  const handleCloseProfileMenu = () => {
    setProfileMenuAnchor(null)
  }

  const handleLogoutClick = () => {
    handleCloseProfileMenu()
    onLogout()
  }

  const handleSettingsClick = () => {
    handleCloseProfileMenu()
    setCurrentView('settings')
    if (isMobile) {
      setIsOpen(false)
    }
  }

  const menuItems = [
    {
      id: 'upload',
      label: 'Upload Log',
      icon: <UploadFileIcon />,
      enabled: !!currentUser
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
         </Box>
      </Toolbar>
      <Divider sx={{ mt: 1, opacity: 0.5 }} />
      <Box sx={{ p: 2.5, flexGrow: 1 }}>
        <Box sx={{ px: 1.5, mb: 4.0 }}>
          <Typography variant="overline" color="text.secondary">
            Workspace
          </Typography>
        </Box>

        <List sx={{ mb: 1 }}>
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

        <Divider sx={{ my: 2 }} />
        <Box sx={{ px: 1.5 }}>
          <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ mb: 1 }}>
            <Stack direction="row" spacing={1} alignItems="center">
              <HistoryRoundedIcon sx={{ fontSize: 18, color: 'text.secondary' }} />
              <Typography variant="overline" color="text.secondary">
                Session
              </Typography>
            </Stack>
            <Tooltip title="Refresh sessions">
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
              {currentUser ? 'No saved sessions yet.' : 'Login to view your saved sessions.'}
            </Typography>
          )}

          <List disablePadding sx={{ maxHeight: 300, overflowY: 'auto', pr: 0.5 }}>
            {sessions.map((item) => {
              const selected = item.session_id === sessionId
              const title = item.title || item.file_name || item.session_id

              return (
                <ListItem key={item.session_id} disablePadding sx={{ mb: 0.5 }}>
                  <ListItemButton
                    selected={selected}
                    onClick={() => onSelectSession(item.session_id)}
                    title={title}
                    sx={{
                      position: 'relative',
                      alignItems: 'center',
                      borderRadius: 2,
                      border: '1px solid transparent',
                      borderColor: selected ? 'rgba(147, 197, 253, 0.3)' : 'transparent',
                      bgcolor: selected ? 'rgba(37, 99, 235, 0.16)' : 'transparent',
                      minHeight: 40,
                      px: 1.25,
                      py: 0.45,
                      overflow: 'hidden',
                      '&:hover, &:focus-visible': {
                        bgcolor: selected ? 'rgba(37, 99, 235, 0.2)' : 'rgba(148, 163, 184, 0.08)',
                      },
                      '&:hover .session-actions, &:focus-visible .session-actions, &.Mui-selected .session-actions': {
                        opacity: 1,
                        pointerEvents: 'auto',
                      },
                    }}
                  >
                    <ListItemText
                      primary={title}
                      className="session-title"
                      sx={{
                        minWidth: 0,
                        mr: 0,
                        pr: 6.5,
                        '& .MuiListItemText-primary': {
                          maxWidth: '100%',
                        },
                      }}
                      primaryTypographyProps={{
                        fontSize: '0.84rem',
                        fontWeight: selected ? 700 : 600,
                        noWrap: true,
                        title,
                        sx: {
                          color: '#F8FAFC',
                          lineHeight: 1.35,
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                        },
                      }}
                    />
                    <Stack
                      className="session-actions"
                      direction="row"
                      spacing={0.25}
                      alignItems="center"
                      onClick={(event) => event.stopPropagation()}
                      sx={{
                        position: 'absolute',
                        right: 6,
                        top: '50%',
                        transform: 'translateY(-50%)',
                        pl: 2,
                        opacity: selected ? 1 : 0,
                        pointerEvents: selected ? 'auto' : 'none',
                        transition: 'opacity 140ms ease',
                        background: '#0B1220',
                      }}
                    >
                      <Tooltip title="Rename session">
                        <IconButton
                          size="small"
                          onClick={(event) => handleRenameSession(event, item)}
                          sx={{
                            p: 0.35,
                            bgcolor: 'rgba(15, 23, 42, 0.72)',
                            '&:hover': { bgcolor: 'rgba(30, 41, 59, 0.96)' },
                          }}
                        >
                          <EditRoundedIcon sx={{ fontSize: 16 }} />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Delete session and saved files">
                        <IconButton
                          size="small"
                          color="error"
                          onClick={(event) => handleDeleteSession(event, item)}
                          sx={{
                            p: 0.35,
                            bgcolor: 'rgba(15, 23, 42, 0.72)',
                            '&:hover': { bgcolor: 'rgba(127, 29, 29, 0.34)' },
                          }}
                        >
                          <DeleteOutlineRoundedIcon sx={{ fontSize: 16 }} />
                        </IconButton>
                      </Tooltip>
                    </Stack>
                  </ListItemButton>
                </ListItem>
              )
            })}
          </List>
        </Box>
      </Box>
      
      <Box sx={{ borderTop: '1px solid', borderColor: 'divider' }}>
        <Box sx={{ px: 2.5, py: 2.5 }}>
          {currentUser ? (
            <>
              <Button
                fullWidth
                onClick={handleOpenProfileMenu}
                sx={{
                  justifyContent: 'flex-start',
                  mb: 2,
                  px: 1,
                  py: 1,
                  borderRadius: 2,
                  textTransform: 'none',
                  color: 'inherit',
                  '&:hover': {
                    bgcolor: 'rgba(148, 163, 184, 0.08)',
                  },
                }}
              >
                <Stack direction="row" spacing={1.2} alignItems="center" sx={{ minWidth: 0, width: '100%' }}>
            <AccountCircleRoundedIcon sx={{ color: '#bfdbfe' }} />
                <Box sx={{ minWidth: 0, flexGrow: 1, textAlign: 'left' }}>
                  <Typography variant="subtitle2" noWrap sx={{ color: '#F8FAFC', fontWeight: 800 }}>
                    {currentUser.name || 'Analyst'}
                  </Typography>
                  <Typography variant="caption" noWrap display="block" sx={{ color: '#94A3B8' }}>
                    {currentUser.username || currentUser.email}
                  </Typography>
                </Box>
                </Stack>
              </Button>
              <Menu
                anchorEl={profileMenuAnchor}
                open={profileMenuOpen}
                onClose={handleCloseProfileMenu}
                anchorOrigin={{ vertical: 'top', horizontal: 'left' }}
                transformOrigin={{ vertical: 'bottom', horizontal: 'left' }}
                PaperProps={{
                  sx: {
                    minWidth: 190,
                    bgcolor: '#0F172A',
                    border: '1px solid rgba(148, 163, 184, 0.18)',
                  },
                }}
              >
                <MenuItem
                  selected={currentView === 'settings'}
                  onClick={handleSettingsClick}
                  sx={{ gap: 1 }}
                >
                  <SettingsRoundedIcon fontSize="small" />
                  Settings
                </MenuItem>
                <MenuItem onClick={handleLogoutClick} sx={{ color: '#FCA5A5', gap: 1 }}>
                  <LogoutRoundedIcon fontSize="small" />
                  Logout
                </MenuItem>
              </Menu>
            </>
          ) : (
            <Box
              sx={{
                p: 1.5,
                mb: 2,
                borderRadius: 2,
                bgcolor: 'rgba(15, 23, 42, 0.46)',
                border: '1px solid rgba(148, 163, 184, 0.14)',
              }}
            >
              <Typography variant="subtitle2" sx={{ color: '#E2E8F0', fontWeight: 800 }}>
                No active profile
              </Typography>
              <Typography variant="caption" sx={{ color: '#94A3B8' }}>
                Login after Start Investigation to save history.
              </Typography>
            </Box>
          )}
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
