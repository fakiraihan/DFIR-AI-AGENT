import { AppBar, Toolbar, IconButton, Typography, Box, Chip, Stack, Slide } from '@mui/material'
import MenuIcon from '@mui/icons-material/Menu'
import VerifiedRoundedIcon from '@mui/icons-material/VerifiedRounded'
import RadarIcon from '@mui/icons-material/Radar'

const Header = ({ sidebarOpen, setSidebarOpen, drawerWidth, currentView = 'upload', showShell = true }) => {

  return (
    <Slide in={showShell} direction="down">
      <AppBar 
        position="fixed" 
        sx={{ 
          zIndex: (theme) => theme.zIndex.drawer + 1,
          bgcolor: 'rgba(7, 11, 20, 0.7)',
          backdropFilter: 'blur(16px)',
          borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
          boxShadow: 'none',
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
            border: '1px solid rgba(255, 255, 255, 0.1)',
            bgcolor: 'rgba(255,255,255,0.03)',
            borderRadius: 2,
            '&:hover': {
              bgcolor: 'rgba(255,255,255,0.08)'
            }
          }}
        >
          <MenuIcon />
        </IconButton>

        <Box sx={{ display: 'flex', flexDirection: 'row', alignItems: 'center', flexGrow: 1, minWidth: 0 }}>
          <RadarIcon sx={{ color: '#06b6d4', mr: 1.5, fontSize: 32 }} />
          <Box sx={{ display: 'flex', flexDirection: 'column' }}>
            <Typography variant="h5" noWrap component="div" sx={{ fontWeight: 800, color: '#F8FAFC', lineHeight: 1.2, letterSpacing: '-0.02em' }}>
              Anomalyze Agent
            </Typography>
            <Typography variant="caption" noWrap sx={{ color: '#06b6d4', fontWeight: 600, letterSpacing: '0.05em', textTransform: 'uppercase' }}>
              Cyber Incident Investigation
            </Typography>
          </Box>
        </Box>

        <Stack direction="row" spacing={2} alignItems="center">
          <Chip
            icon={<VerifiedRoundedIcon fontSize="small" />}
            label="System Online"
            variant="outlined"
            size="small"
            sx={{
              borderColor: 'rgba(16, 185, 129, 0.3)',
              bgcolor: 'rgba(16, 185, 129, 0.08)',
              color: '#34d399',
              '& .MuiChip-icon': { color: '#34d399' },
              display: { xs: 'none', sm: 'inline-flex' },
              backdropFilter: 'blur(4px)',
            }}
          />
        </Stack>
      </Toolbar>
    </AppBar>
    </Slide>
  )
}

export default Header
