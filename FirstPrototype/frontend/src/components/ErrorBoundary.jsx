import React from 'react'
import { Box, Button, Paper, Stack, Typography } from '@mui/material'
import ErrorOutlineIcon from '@mui/icons-material/ErrorOutline'

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props)
    this.state = {
      hasError: false,
    }
  }

  static getDerivedStateFromError() {
    return {
      hasError: true,
    }
  }

  componentDidCatch(error, errorInfo) {
    console.error('Application render error:', error, errorInfo)
  }

  handleReload = () => {
    window.location.reload()
  }

  render() {
    if (this.state.hasError) {
      return (
        <Box
          sx={{
            minHeight: '100vh',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            px: 2,
            bgcolor: 'background.default',
          }}
        >
          <Paper elevation={0} sx={{ maxWidth: 560, width: '100%', p: { xs: 3, md: 4 }, borderRadius: 3 }}>
            <Stack spacing={2.5} alignItems="flex-start">
              <ErrorOutlineIcon sx={{ fontSize: 48, color: 'error.main' }} />
              <Box>
                <Typography variant="h5" gutterBottom>
                  The investigation workspace hit a runtime error
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Try reloading the page to resume the session. If the problem persists, start a new upload or review the backend response for malformed investigation data.
                </Typography>
              </Box>
              <Button variant="contained" onClick={this.handleReload}>
                Reload application
              </Button>
            </Stack>
          </Paper>
        </Box>
      )
    }

    return this.props.children
  }
}

export default ErrorBoundary
