import { createTheme } from '@mui/material/styles';

let theme = createTheme({
  palette: {
    mode: 'dark',
    primary: {
      main: '#2563eb',
      light: '#bfdbfe',
      dark: '#1d4ed8',
      contrastText: '#ffffff',
    },
    secondary: {
      main: '#818cf8', // indigo-400
      light: '#a5b4fc', // indigo-300
      dark: '#6366f1', // indigo-500
      contrastText: '#ffffff',
    },
    background: {
      default: '#070b14', // very dark navy
      paper: 'rgba(15, 23, 42, 0.62)', // translucent dark surface
    },
    error: {
      main: '#f43f5e', // rose-500
    },
    warning: {
      main: '#f59e0b', // amber-500
    },
    info: {
      main: '#3b82f6', // blue-500
    },
    success: {
      main: '#10b981', // emerald-500
    },
    text: {
      primary: '#F8FAFC', // slate-50
      secondary: '#CBD5E1', // slate-300
    },
    divider: 'rgba(255, 255, 255, 0.10)',
  },
  typography: {
    fontFamily: [
      '"Segoe UI Variable"',
      'Aptos',
      '-apple-system',
      'BlinkMacSystemFont',
      '"Segoe UI"',
      '"Helvetica Neue"',
      'Arial',
      'sans-serif',
      '"Apple Color Emoji"',
      '"Segoe UI Emoji"',
      '"Segoe UI Symbol"',
    ].join(','),
    h1: { fontWeight: 700, fontSize: '2.75rem', letterSpacing: 0 },
    h2: { fontWeight: 700, fontSize: '2.2rem', letterSpacing: 0 },
    h3: { fontWeight: 700, fontSize: '1.75rem', letterSpacing: 0 },
    h4: { fontWeight: 700, fontSize: '1.4rem', letterSpacing: 0 },
    h5: { fontWeight: 600, fontSize: '1.1rem', letterSpacing: 0 },
    h6: { fontWeight: 600, fontSize: '1rem' },
    subtitle1: { fontWeight: 600 },
    subtitle2: { fontWeight: 600, letterSpacing: 0 },
    body1: { lineHeight: 1.7 },
    body2: { lineHeight: 1.6 },
    button: { textTransform: 'none', fontWeight: 600, letterSpacing: 0 },
    overline: { letterSpacing: 0, fontWeight: 700, fontSize: '0.72rem' },
  },
  shape: {
    borderRadius: 12,
  },
  components: {
    MuiCssBaseline: {
      styleOverrides: {
        body: {
          backgroundColor: '#070b14',
          minHeight: '100vh',
        },
        '::selection': {
          backgroundColor: 'rgba(37, 99, 235, 0.32)',
        },
        '*::-webkit-scrollbar': {
          width: 8,
          height: 8,
        },
        '*::-webkit-scrollbar-track': {
          backgroundColor: 'transparent',
        },
        '*::-webkit-scrollbar-thumb': {
          backgroundColor: 'rgba(255, 255, 255, 0.1)',
          borderRadius: 999,
          border: '2px solid transparent',
          backgroundClip: 'padding-box',
        },
        '*::-webkit-scrollbar-thumb:hover': {
          backgroundColor: 'rgba(255, 255, 255, 0.2)',
        },
      },
    },
    MuiButton: {
      styleOverrides: {
        root: {
          borderRadius: 12,
          padding: '8px 18px',
          transition: 'background-color 0.2s ease, border-color 0.2s ease, color 0.2s ease, box-shadow 0.2s ease, transform 0.2s ease',
        },
        containedPrimary: {
          boxShadow: 'none',
          backgroundImage: 'none',
          backgroundColor: '#2563eb',
          color: '#ffffff',
          border: 'none',
          '&:hover': {
            boxShadow: '0 0 0 1px rgba(147, 197, 253, 0.34)',
            backgroundImage: 'none',
            backgroundColor: '#1d4ed8',
          },
          '&.Mui-disabled': {
            backgroundColor: 'rgba(255, 255, 255, 0.05)',
            backgroundImage: 'none',
            color: 'rgba(255, 255, 255, 0.3)',
            boxShadow: 'none',
          }
        },
        outlinedPrimary: {
          borderColor: 'rgba(147, 197, 253, 0.26)',
          backgroundColor: 'rgba(15, 23, 42, 0.72)',
          color: '#bfdbfe',
          '&:hover': {
            borderColor: 'rgba(147, 197, 253, 0.58)',
            backgroundColor: 'rgba(37, 99, 235, 0.12)',
          },
        },
        text: {
          color: '#CBD5E1',
          '&:hover': {
            backgroundColor: 'rgba(255, 255, 255, 0.05)',
            color: '#F8FAFC',
          }
        }
      },
    },
    MuiCard: {
      styleOverrides: {
        root: {
          backgroundImage: 'none',
          boxShadow: 'none',
          border: '1px solid rgba(148, 163, 184, 0.16)',
          backgroundColor: 'rgba(15, 23, 42, 0.84)',
          borderRadius: 12,
        },
      },
    },
    MuiPaper: {
      styleOverrides: {
        root: {
          backgroundImage: 'none',
          boxShadow: 'none',
          border: '1px solid rgba(148, 163, 184, 0.16)',
          backgroundColor: 'rgba(15, 23, 42, 0.84)',
        },
      },
    },
    MuiAppBar: {
      styleOverrides: {
        root: {
          backgroundColor: 'rgba(7, 11, 20, 0.7)',
          backgroundImage: 'none',
          borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
          boxShadow: 'none',
        },
      },
    },
    MuiDrawer: {
      styleOverrides: {
        paper: {
          backgroundColor: '#0b0f19',
          borderRight: '1px solid rgba(255, 255, 255, 0.08)',
        },
      },
    },
    MuiListItemButton: {
      styleOverrides: {
        root: {
          borderRadius: 10,
          margin: '4px 8px',
          minHeight: 44,
          border: '1px solid transparent',
          transition: 'background-color 0.2s ease, color 0.2s ease, border-color 0.2s ease, box-shadow 0.2s ease',
          '&.Mui-selected': {
            backgroundColor: 'rgba(37, 99, 235, 0.16)',
            color: '#bfdbfe',
            borderColor: 'rgba(147, 197, 253, 0.3)',
            boxShadow: 'inset 0 0 0 1px rgba(147, 197, 253, 0.14)',
            '&:hover': {
              backgroundColor: 'rgba(37, 99, 235, 0.2)',
            },
          },
          '&:hover': {
            backgroundColor: 'rgba(255, 255, 255, 0.04)',
          },
        },
      },
    },
    MuiChip: {
      styleOverrides: {
        root: {
          fontWeight: 600,
          borderRadius: 8,
        },
        outlined: {
          borderColor: 'rgba(255, 255, 255, 0.15)',
          backgroundColor: 'rgba(15, 23, 42, 0.4)',
        },
      },
    },
    MuiLinearProgress: {
      styleOverrides: {
        root: {
          backgroundColor: 'rgba(255, 255, 255, 0.05)',
          overflow: 'hidden',
          borderRadius: 999,
        },
        bar: {
          borderRadius: 999,
          position: 'relative',
          overflow: 'hidden',
          backgroundImage: 'none',
          backgroundColor: '#2563eb',
          boxShadow: 'none',
          transition: 'transform 400ms cubic-bezier(0.4, 0, 0.2, 1)',
        },
      },
    },
    MuiAlert: {
      styleOverrides: {
        root: {
          borderRadius: 12,
          border: '1px solid',
        },
        standardError: {
          backgroundColor: 'rgba(244, 63, 94, 0.1)',
          borderColor: 'rgba(244, 63, 94, 0.2)',
          color: '#fecdd3',
          '& .MuiAlert-icon': {
            color: '#fb7185',
          }
        },
        standardWarning: {
          backgroundColor: 'rgba(245, 158, 11, 0.1)',
          borderColor: 'rgba(245, 158, 11, 0.2)',
          color: '#fde68a',
          '& .MuiAlert-icon': {
            color: '#fbbf24',
          }
        },
        standardInfo: {
          backgroundColor: 'rgba(59, 130, 246, 0.1)',
          borderColor: 'rgba(59, 130, 246, 0.2)',
          color: '#bfdbfe',
          '& .MuiAlert-icon': {
            color: '#60a5fa',
          }
        },
        standardSuccess: {
          backgroundColor: 'rgba(16, 185, 129, 0.1)',
          borderColor: 'rgba(16, 185, 129, 0.2)',
          color: '#a7f3d0',
          '& .MuiAlert-icon': {
            color: '#34d399',
          }
        }
      }
    }
  },
});

export default theme;
