import { createTheme } from '@mui/material/styles';

let theme = createTheme({
  palette: {
    mode: 'dark',
    primary: {
      main: '#06b6d4', // cyan-500
      light: '#22d3ee', // cyan-400
      dark: '#0891b2', // cyan-600
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
      'Inter',
      '-apple-system',
      'BlinkMacSystemFont',
      '"Segoe UI"',
      'Roboto',
      '"Helvetica Neue"',
      'Arial',
      'sans-serif',
      '"Apple Color Emoji"',
      '"Segoe UI Emoji"',
      '"Segoe UI Symbol"',
    ].join(','),
    h1: { fontWeight: 700, fontSize: '2.75rem', letterSpacing: '-0.04em' },
    h2: { fontWeight: 700, fontSize: '2.2rem', letterSpacing: '-0.04em' },
    h3: { fontWeight: 700, fontSize: '1.75rem', letterSpacing: '-0.03em' },
    h4: { fontWeight: 700, fontSize: '1.4rem', letterSpacing: '-0.02em' },
    h5: { fontWeight: 600, fontSize: '1.1rem', letterSpacing: '-0.01em' },
    h6: { fontWeight: 600, fontSize: '1rem' },
    subtitle1: { fontWeight: 600 },
    subtitle2: { fontWeight: 600, letterSpacing: '-0.01em' },
    body1: { lineHeight: 1.7 },
    body2: { lineHeight: 1.6 },
    button: { textTransform: 'none', fontWeight: 600, letterSpacing: '-0.01em' },
    overline: { letterSpacing: '0.12em', fontWeight: 700, fontSize: '0.68rem' },
  },
  shape: {
    borderRadius: 12,
  },
  components: {
    MuiCssBaseline: {
      styleOverrides: {
        body: {
          backgroundColor: '#070b14',
          backgroundImage: `
            radial-gradient(circle at top right, rgba(6, 182, 212, 0.08) 0%, transparent 40%),
            radial-gradient(circle at bottom left, rgba(99, 102, 241, 0.08) 0%, transparent 40%)
          `,
          backgroundAttachment: 'fixed',
          minHeight: '100vh',
        },
        '::selection': {
          backgroundColor: 'rgba(6, 182, 212, 0.25)',
        },
        '@keyframes progressGlowSweep': {
          '0%': { transform: 'translateX(-120%)' },
          '100%': { transform: 'translateX(120%)' },
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
          transition: 'all 0.2s ease-in-out',
        },
        containedPrimary: {
          boxShadow: '0 4px 14px 0 rgba(6, 182, 212, 0.39)',
          backgroundImage: 'linear-gradient(135deg, #22d3ee 0%, #06b6d4 100%)',
          color: '#ffffff',
          border: 'none',
          '&:hover': {
            boxShadow: '0 6px 20px rgba(6, 182, 212, 0.5)',
            backgroundImage: 'linear-gradient(135deg, #67e8f9 0%, #0891b2 100%)',
          },
          '&.Mui-disabled': {
            backgroundColor: 'rgba(255, 255, 255, 0.05)',
            backgroundImage: 'none',
            color: 'rgba(255, 255, 255, 0.3)',
            boxShadow: 'none',
          }
        },
        outlinedPrimary: {
          borderColor: 'rgba(6, 182, 212, 0.3)',
          backgroundColor: 'rgba(15, 23, 42, 0.4)',
          backdropFilter: 'blur(10px)',
          color: '#22d3ee',
          '&:hover': {
            borderColor: 'rgba(6, 182, 212, 0.8)',
            backgroundColor: 'rgba(6, 182, 212, 0.1)',
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
          boxShadow: '0 24px 80px rgba(2, 8, 23, 0.45), 0 0 40px rgba(56, 189, 248, 0.06)',
          border: '1px solid rgba(148, 163, 184, 0.16)',
          backgroundColor: 'rgba(15, 23, 42, 0.62)',
          backdropFilter: 'blur(14px)',
          borderRadius: 24,
        },
      },
    },
    MuiPaper: {
      styleOverrides: {
        root: {
          backgroundImage: 'none',
          boxShadow: '0 24px 80px rgba(2, 8, 23, 0.45), 0 0 40px rgba(56, 189, 248, 0.06)',
          border: '1px solid rgba(148, 163, 184, 0.16)',
          backgroundColor: 'rgba(15, 23, 42, 0.62)',
          backdropFilter: 'blur(14px)',
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
          backdropFilter: 'blur(14px)',
        },
      },
    },
    MuiDrawer: {
      styleOverrides: {
        paper: {
          backgroundColor: 'rgba(11, 15, 25, 0.85)',
          backdropFilter: 'blur(16px)',
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
          transition: 'all 0.2s ease',
          '&.Mui-selected': {
            backgroundColor: 'rgba(6, 182, 212, 0.10)',
            color: '#22d3ee',
            borderLeft: '3px solid #06b6d4',
            '&:hover': {
              backgroundColor: 'rgba(6, 182, 212, 0.15)',
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
          backdropFilter: 'blur(4px)',
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
          backgroundImage: 'linear-gradient(90deg, #6366f1 0%, #06b6d4 100%)',
          boxShadow: '0 0 16px rgba(6, 182, 212, 0.4)',
          transition: 'transform 400ms cubic-bezier(0.4, 0, 0.2, 1)',
          '&::after': {
            content: '""',
            position: 'absolute',
            inset: 0,
            background: 'linear-gradient(90deg, transparent 0%, rgba(255, 255, 255, 0.4) 50%, transparent 100%)',
            animation: 'progressGlowSweep 2s ease-in-out infinite',
          },
        },
      },
    },
    MuiAlert: {
      styleOverrides: {
        root: {
          borderRadius: 12,
          backdropFilter: 'blur(10px)',
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
