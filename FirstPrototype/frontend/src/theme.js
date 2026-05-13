import { createTheme } from '@mui/material/styles';

let theme = createTheme({
  palette: {
    mode: 'dark',
    primary: {
      main: '#00b8d9',
      light: '#7dd3fc',
      dark: '#0891b2',
      contrastText: '#ffffff',
    },
    secondary: {
      main: '#667085',
      light: '#98a2b3',
      dark: '#475467',
      contrastText: '#ffffff',
    },
    background: {
      default: '#0b1117',
      paper: '#121a23',
    },
    error: {
      main: '#f97066',
    },
    warning: {
      main: '#f79009',
    },
    info: {
      main: '#53b1fd',
    },
    success: {
      main: '#32d583',
    },
    text: {
      primary: '#e7ecf3',
      secondary: '#98a2b3',
    },
    divider: 'rgba(152, 162, 179, 0.16)',
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
          backgroundColor: '#0b1117',
          backgroundImage: 'radial-gradient(circle at top, rgba(0, 184, 217, 0.08), transparent 24%)',
        },
        '::selection': {
          backgroundColor: 'rgba(0, 184, 217, 0.25)',
        },
        '@keyframes progressGlowSweep': {
          '0%': {
            transform: 'translateX(-120%)',
          },
          '100%': {
            transform: 'translateX(120%)',
          },
        },
        '*::-webkit-scrollbar': {
          width: 10,
          height: 10,
        },
        '*::-webkit-scrollbar-thumb': {
          backgroundColor: 'rgba(152, 162, 179, 0.24)',
          borderRadius: 999,
          border: '2px solid transparent',
          backgroundClip: 'padding-box',
        },
      },
    },
    MuiButton: {
      styleOverrides: {
        root: {
          borderRadius: 10,
          padding: '9px 16px',
        },
        contained: {
          boxShadow: 'none',
          backgroundImage: 'linear-gradient(135deg, #7dd3fc 0%, #00b8d9 100%)',
          color: '#06212a',
          '&:hover': {
            boxShadow: 'none',
            backgroundImage: 'linear-gradient(135deg, #a5e9ff 0%, #15c8eb 100%)',
          },
        },
        outlined: {
          borderColor: 'rgba(152, 162, 179, 0.18)',
          backgroundColor: 'rgba(18, 26, 35, 0.85)',
          '&:hover': {
            borderColor: 'rgba(0, 184, 217, 0.32)',
            backgroundColor: 'rgba(0, 184, 217, 0.08)',
          },
        },
      },
    },
    MuiCard: {
      styleOverrides: {
        root: {
          backgroundImage: 'none',
          boxShadow: 'none',
          border: '1px solid rgba(152, 162, 179, 0.12)',
          backgroundColor: '#121a23',
        },
      },
    },
    MuiPaper: {
      styleOverrides: {
        root: {
          backgroundImage: 'none',
          border: '1px solid rgba(152, 162, 179, 0.12)',
          backgroundColor: '#121a23',
        },
      },
    },
    MuiAppBar: {
      styleOverrides: {
        root: {
          backgroundColor: 'rgba(11, 17, 23, 0.88)',
          backgroundImage: 'none',
          borderBottom: '1px solid rgba(152, 162, 179, 0.14)',
          boxShadow: 'none',
          backdropFilter: 'blur(14px)',
        },
      },
    },
    MuiDrawer: {
      styleOverrides: {
        paper: {
          backgroundColor: '#101720',
          borderRight: '1px solid rgba(152, 162, 179, 0.14)',
        },
      },
    },
    MuiListItemButton: {
      styleOverrides: {
        root: {
          borderRadius: 10,
          margin: '4px 8px',
          minHeight: 44,
          '&.Mui-selected': {
            backgroundColor: 'rgba(0, 184, 217, 0.10)',
            color: '#7dd3fc',
            '&:hover': {
              backgroundColor: 'rgba(0, 184, 217, 0.14)',
            },
          },
          '&:hover': {
            backgroundColor: 'rgba(152, 162, 179, 0.08)',
          },
        },
      },
    },
    MuiChip: {
      styleOverrides: {
        root: {
          fontWeight: 500,
          borderRadius: 8,
        },
        outlined: {
          borderColor: 'rgba(152, 162, 179, 0.18)',
          backgroundColor: 'rgba(16, 23, 32, 0.72)',
        },
      },
    },
    MuiLinearProgress: {
      styleOverrides: {
        root: {
          backgroundColor: 'rgba(152, 162, 179, 0.10)',
          overflow: 'hidden',
        },
        bar: {
          borderRadius: 999,
          position: 'relative',
          overflow: 'hidden',
          backgroundImage: 'linear-gradient(90deg, #0891b2 0%, #00b8d9 45%, #7dd3fc 100%)',
          boxShadow: '0 0 16px rgba(0, 184, 217, 0.32)',
          transition: 'transform 900ms cubic-bezier(0.22, 1, 0.36, 1)',
          '&::after': {
            content: '""',
            position: 'absolute',
            inset: 0,
            background: 'linear-gradient(90deg, transparent 0%, rgba(255, 255, 255, 0.34) 48%, transparent 100%)',
            animation: 'progressGlowSweep 1.8s ease-in-out infinite',
          },
          '@media (prefers-reduced-motion: reduce)': {
            transition: 'none',
            '&::after': {
              animation: 'none',
            },
          },
        },
      },
    },
  },
});

theme = createTheme(theme, {
  palette: {
    surface: {
      1: '#121a23',
      2: '#0f1720',
      3: '#16212c',
    },
  },
});

export default theme;
