import { AppBar, Toolbar, IconButton, Box, Chip, Stack, Slide } from '@mui/material'
import MenuIcon from '@mui/icons-material/Menu'
import VerifiedRoundedIcon from '@mui/icons-material/VerifiedRounded'
import jejakAgentLogo from '../../jejakAgentv3.png'

const Header = ({ sidebarOpen, setSidebarOpen, showShell = true }) => (
  <Slide in={showShell} direction="down">
    <AppBar
      position="fixed"
      sx={{
        zIndex: (theme) => theme.zIndex.drawer + 1,
        bgcolor: 'rgba(7, 11, 20, 0.7)',
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
              bgcolor: 'rgba(255,255,255,0.08)',
            },
          }}
        >
          <MenuIcon />
        </IconButton>

        <Box sx={{ display: 'flex', flexDirection: 'row', alignItems: 'center', flexGrow: 1, minWidth: 0 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', minWidth: 0 }}>
            <Box
              component="img"
              src={jejakAgentLogo}
              alt="JejakAgent"
              sx={{
                width: { xs: 176, sm: 230 },
                height: 48,
                objectFit: 'contain',
                objectPosition: 'left center',
              }}
            />
          </Box>
        </Box>

      </Toolbar>
    </AppBar>
  </Slide>
)

export default Header
