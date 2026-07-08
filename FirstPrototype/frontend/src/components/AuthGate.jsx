import React, { useState } from 'react'
import axios from 'axios'
import {
  Alert,
  Box,
  Button,
  Container,
  Paper,
  Stack,
  Tab,
  Tabs,
  TextField,
  Typography,
} from '@mui/material'
import LoginRoundedIcon from '@mui/icons-material/LoginRounded'
import PersonAddAlt1RoundedIcon from '@mui/icons-material/PersonAddAlt1Rounded'
import jejakAgentLogo from '../../jejakAgentv3.png'

const AuthGate = ({ onAuthenticated }) => {
  const [mode, setMode] = useState('login')
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const isRegister = mode === 'register'

  const handleSubmit = async (event) => {
    event.preventDefault()
    setError('')
    setLoading(true)

    try {
      const endpoint = isRegister ? '/api/auth/register' : '/api/auth/login'
      const payload = isRegister
        ? { username: username.trim(), email: email.trim(), password }
        : { username: username.trim(), password }
      const response = await axios.post(endpoint, payload)
      onAuthenticated(response.data.user)
    } catch (authError) {
      setError(authError.response?.data?.detail || 'Authentication failed. Please check your details.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <Container
      maxWidth="xs"
      sx={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        py: { xs: 4, md: 8 },
      }}
    >
      <Paper
        elevation={0}
        sx={{
          width: '100%',
          p: { xs: 3, md: 4 },
          borderRadius: 2,
          bgcolor: 'rgba(15, 23, 42, 0.88)',
          border: '1px solid rgba(148, 163, 184, 0.18)',
          boxShadow: 'none',
        }}
      >
        <Stack spacing={3}>
          <Stack spacing={1.5} sx={{ textAlign: 'center', alignItems: 'center' }}>
            <Box
              component="img"
              src={jejakAgentLogo}
              alt="JejakAgent"
              sx={{
                width: '100%',
                maxWidth: 260,
                height: 58,
                objectFit: 'contain',
                mb: 0.5,
              }}
            />
            <Typography variant="h4" sx={{ color: '#F8FAFC', fontWeight: 900, lineHeight: 1.15 }}>
              {isRegister ? 'Create your account' : 'Login to continue'}
            </Typography>
            <Typography variant="body2" sx={{ color: '#94A3B8', lineHeight: 1.6 }}>
              {isRegister ? 'Save each investigation under your own profile.' : 'Enter your account below.'}
            </Typography>
          </Stack>

          <Tabs
            value={mode}
            onChange={(event, value) => {
              setMode(value)
              setError('')
            }}
            sx={{
              minHeight: 44,
              '& .MuiTab-root': { color: '#94A3B8', fontWeight: 800, minHeight: 44 },
              '& .Mui-selected': { color: '#8fbff' },
              '& .MuiTabs-indicator': { bgcolor: '#5087ff' },
            }}
          >
            <Tab value="login" icon={<LoginRoundedIcon />} iconPosition="start" label="Login" />
            <Tab value="register" icon={<PersonAddAlt1RoundedIcon />} iconPosition="start" label="Register" />
          </Tabs>

          {error && <Alert severity="error">{error}</Alert>}

          <Box component="form" onSubmit={handleSubmit} sx={{ display: 'grid', gap: 2 }}>
            <TextField
              label="Username"
              name="username"
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              required
              fullWidth
              inputProps={{ minLength: 3, maxLength: 40 }}
            />
            {isRegister && (
              <TextField
                label="Email"
                name="email"
                type="email"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                required
                fullWidth
              />
            )}
            <TextField
              label="Password"
              name="password"
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              required
              fullWidth
              inputProps={{ minLength: 8 }}
            />
            <Button
              type="submit"
              variant="contained"
              size="large"
              disabled={loading}
              sx={{ py: 1.5, fontWeight: 900 }}
            >
              {loading ? 'Please wait...' : isRegister ? 'Register' : 'Login'}
            </Button>
          </Box>
        </Stack>
      </Paper>
    </Container>
  )
}

export default AuthGate
