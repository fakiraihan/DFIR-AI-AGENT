import React from 'react'
import { Drawer, List, ListItem, ListItemButton, ListItemIcon, ListItemText, Typography, Box, Divider, Toolbar, Chip, Stack } from '@mui/material'
import UploadFileIcon from '@mui/icons-material/UploadFile'
import SearchIcon from '@mui/icons-material/Search'
import SettingsRoundedIcon from '@mui/icons-material/SettingsRounded'
import FolderOpenOutlinedIcon from '@mui/icons-material/FolderOpenOutlined'

const Sidebar = ({ isOpen, setIsOpen, currentView, setCurrentView, sessionId, drawerWidth, isMobile }) => {
  const sessionDisplay = sessionId
    ? sessionId.length > 18
      ? `${sessionId.slice(0, 8)}...${sessionId.slice(-6)}`
      : sessionId
    : null

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
      <Toolbar /> {/* Spacer for AppBar */}
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
            <Divider sx={{ my: 2 }} />
            <Box sx={{ px: 1.5 }}>
              <Typography variant="overline" color="text.secondary">
                Active session
              </Typography>
              <Box
                sx={{
                  mt: 1,
                  p: 1.75,
                  borderRadius: 2.5,
                  bgcolor: 'rgba(255,255,255,0.02)',
                  border: '1px solid',
                  borderColor: 'divider',
                }}
              >
                <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1.25 }}>
                  <FolderOpenOutlinedIcon sx={{ fontSize: 18, color: 'primary.main' }} />
                  <Typography variant="subtitle2">Current investigation</Typography>
                </Stack>
                <Chip label="In progress" size="small" variant="outlined" sx={{ mb: 1.5 }} />
                <Typography variant="caption" color="text.secondary" display="block">
                  Session ID
                </Typography>
                <Typography variant="body2" sx={{ fontFamily: 'monospace', wordBreak: 'break-all' }} title={sessionId}>
                  {sessionDisplay}
                </Typography>
              </Box>
            </Box>
          </>
        )}
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
    <Box component="nav" sx={{ width: { md: drawerWidth }, flexShrink: { md: 0 } }}>
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
