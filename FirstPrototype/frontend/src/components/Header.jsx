import React from 'react'
import { AppBar, Toolbar, IconButton, Typography, Box, Chip } from '@mui/material'
import MenuIcon from '@mui/icons-material/Menu'
import SecurityIcon from '@mui/icons-material/Security'
import VerifiedRoundedIcon from '@mui/icons-material/VerifiedRounded'

const Header = ({ sidebarOpen, setSidebarOpen }) => {
  return (
    <AppBar 
      position="fixed" 
      sx={{ 
        zIndex: (theme) => theme.zIndex.drawer + 1,
        borderBottom: 1,
        borderColor: 'divider',
        bgcolor: 'background.paper'
      }}
    >
      <Toolbar>
        <IconButton
          color="inherit"
          aria-label="Toggle sidebar"
          edge="start"
          onClick={() => setSidebarOpen(!sidebarOpen)}
          sx={{ 
            mr: 2,
            border: '1px solid',
            borderColor: 'divider',
            bgcolor: 'rgba(255,255,255,0.02)'
          }}
        >
          <MenuIcon />
        </IconButton>

        <Box sx={{ display: 'flex', alignItems: 'center', flexGrow: 1, minWidth: 0 }}>
          <SecurityIcon sx={{ color: 'primary.main', mr: 1.5, fontSize: 22 }} />
          <Typography variant="h6" noWrap component="div" sx={{ fontWeight: 700 }}>
            Anomalyze Agent
          </Typography>
        </Box>

        <Chip
          icon={<VerifiedRoundedIcon />}
          label="System healthy"
          variant="outlined"
          sx={{
            '& .MuiChip-icon': { color: 'success.main' },
            display: { xs: 'none', sm: 'inline-flex' },
          }}
        />
      </Toolbar>
    </AppBar>
  )
}

export default Header
