import React, { useEffect, useMemo, useState } from 'react'
import axios from 'axios'
import {
  Alert,
  Box,
  Button,
  Chip,
  FormControl,
  Grid,
  InputLabel,
  MenuItem,
  Paper,
  Select,
  Stack,
  TextField,
  Typography,
} from '@mui/material'
import CheckCircleOutlineRoundedIcon from '@mui/icons-material/CheckCircleOutlineRounded'
import ErrorOutlineRoundedIcon from '@mui/icons-material/ErrorOutlineRounded'
import RefreshRoundedIcon from '@mui/icons-material/RefreshRounded'
import SaveRoundedIcon from '@mui/icons-material/SaveRounded'

const emptyProviderForm = {
  ollama: { enabled: true, base_url: 'http://localhost:11434', model: '' },
  gemini: { enabled: false, model: '', api_key: '', has_api_key: false },
  openrouter: { enabled: false, base_url: 'https://openrouter.ai/api/v1', model: '', api_key: '', has_api_key: false },
}

const ProviderLogo = ({ providerKey }) => {
  const size = 28
  switch (providerKey) {
    case 'ollama':
      return (
        <Box sx={{ width: size, height: size, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'text.primary' }}>
          <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" style={{ width: '100%', height: '100%' }}>
            <path d="M5.5 12C5.5 15.5899 8.41015 18.5 12 18.5C15.5899 18.5 18.5 12C18.5 8.41015 15.5899 5.5 12 5.5C8.41015 5.5 5.5 8.41015 5.5 12ZM20 12C20 16.4183 16.4183 20 12 20C7.58172 20 4 16.4183 4 12C4 7.58172 7.58172 4 12 4C16.4183 4 20 7.58172 20 12Z" fill="currentColor"/>
            <circle cx="9.5" cy="10" r="1.5" fill="currentColor"/>
            <circle cx="14.5" cy="10" r="1.5" fill="currentColor"/>
            <path d="M10 14C10 14 11 15 12 15C13 15 14 14 14 14" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
          </svg>
        </Box>
      )
    case 'gemini':
      return (
        <Box sx={{ width: size, height: size, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#10b981' }}>
          <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" style={{ width: '100%', height: '100%' }}>
            <path d="M12 2L14.4 9.6L22 12L14.4 14.4L12 22L9.6 14.4L2 12L9.6 9.6L12 2Z" fill="currentColor"/>
          </svg>
        </Box>
      )
    case 'openrouter':
      return (
        <Box sx={{ width: size, height: size, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#6366f1' }}>
          <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" style={{ width: '100%', height: '100%' }}>
            <path d="M12 2L22 7V17L12 22L2 17V7L12 2Z" stroke="currentColor" strokeWidth="2" strokeLinejoin="round"/>
            <circle cx="12" cy="12" r="3" fill="currentColor"/>
          </svg>
        </Box>
      )
    default:
      return null
  }
}

const getErrorText = (error, fallback) => {
  const detail = error.response?.data?.detail
  if (typeof detail === 'string' && detail.trim()) {
    return detail
  }
  if (error.message) {
    return `${fallback} (${error.message})`
  }
  return fallback
}

const mergeProviderSettings = (settingsData) => ({
  ollama: {
    ...emptyProviderForm.ollama,
    ...settingsData.providers?.ollama,
  },
  gemini: {
    ...emptyProviderForm.gemini,
    ...settingsData.providers?.gemini,
    api_key: '',
  },
  openrouter: {
    ...emptyProviderForm.openrouter,
    ...settingsData.providers?.openrouter,
    api_key: '',
  },
})

function SettingsPage() {
  const [selectedProvider, setSelectedProvider] = useState('ollama')
  const [providers, setProviders] = useState(emptyProviderForm)
  const [providerStatus, setProviderStatus] = useState({})
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [refreshing, setRefreshing] = useState(false)
  const [feedback, setFeedback] = useState(null)

  const loadSettings = async () => {
    setLoading(true)
    setFeedback(null)
    try {
      const { data: settingsData } = await axios.get('/api/settings/llm')

      setSelectedProvider(settingsData.selected_provider || 'ollama')
      setProviders(mergeProviderSettings(settingsData))

      try {
        const { data: statusData } = await axios.get('/api/settings/llm/status')
        setProviderStatus(statusData.providers || {})
      } catch (statusError) {
        setProviderStatus({})
        setFeedback({
          type: 'warning',
          text: getErrorText(statusError, 'LLM settings loaded, but provider health could not be refreshed.'),
        })
      }
    } catch (error) {
      setFeedback({ type: 'error', text: getErrorText(error, 'Failed to load LLM settings.') })
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadSettings()
  }, [])

  const activeProviderStatus = providerStatus[selectedProvider]

  const providerCards = useMemo(() => ([
    {
      key: 'ollama',
      title: 'Ollama',
      helper: 'Local-first runtime for private on-device inference.',
    },
    {
      key: 'gemini',
      title: 'Gemini',
      helper: 'Remote Google model when cloud usage is explicitly selected.',
    },
    {
      key: 'openrouter',
      title: 'OpenRouter',
      helper: 'Remote provider hub for alternate hosted models.',
    },
  ]), [])

  const handleProviderFieldChange = (providerName, field, value) => {
    setProviders((prev) => ({
      ...prev,
      [providerName]: {
        ...prev[providerName],
        [field]: value,
      },
    }))
  }

  const handleSave = async () => {
    setSaving(true)
    setFeedback(null)
    try {
      const payload = {
        selected_provider: selectedProvider,
        providers: {
          ollama: {
            enabled: selectedProvider === 'ollama',
            base_url: providers.ollama.base_url,
            model: providers.ollama.model,
          },
          gemini: {
            enabled: selectedProvider === 'gemini',
            model: providers.gemini.model,
            ...(providers.gemini.api_key ? { api_key: providers.gemini.api_key } : {}),
          },
          openrouter: {
            enabled: selectedProvider === 'openrouter',
            base_url: providers.openrouter.base_url,
            model: providers.openrouter.model,
            ...(providers.openrouter.api_key ? { api_key: providers.openrouter.api_key } : {}),
          },
        },
      }

      await axios.put('/api/settings/llm', payload)
      setFeedback({ type: 'success', text: 'LLM settings saved successfully.' })
      await loadSettings()
    } catch (error) {
      setFeedback({ type: 'error', text: getErrorText(error, 'Failed to save LLM settings.') })
    } finally {
      setSaving(false)
    }
  }

  const handleRefreshStatus = async () => {
    setRefreshing(true)
    try {
      const { data } = await axios.get('/api/settings/llm/status')
      setProviderStatus(data.providers || {})
      setFeedback({ type: 'info', text: 'Provider health refreshed.' })
    } catch (error) {
      setFeedback({ type: 'error', text: getErrorText(error, 'Failed to refresh provider health.') })
    } finally {
      setRefreshing(false)
    }
  }

  if (loading) {
    return (
      <Box sx={{ maxWidth: 1120, mx: 'auto', width: '100%', py: 4 }}>
        <Typography variant="h4">Loading settings...</Typography>
      </Box>
    )
  }

  return (
    <Box sx={{ maxWidth: 1120, mx: 'auto', width: '100%', py: 4 }}>
      <Stack direction={{ xs: 'column', lg: 'row' }} justifyContent="space-between" spacing={3} sx={{ mb: 4 }}>
        <Box sx={{ maxWidth: 760 }}>
          <Typography variant="overline" color="primary.main" sx={{ fontWeight: 600, letterSpacing: '0.05em' }}>
            Provider Configuration
          </Typography>
          <Typography variant="h3" sx={{ mt: 0.75, mb: 1.25, fontWeight: 700, color: '#F8FAFC' }}>
            LLM Routing & Settings
          </Typography>
          <Typography variant="body1" color="text.secondary">
            Keep investigations local-first with Ollama, or select Gemini / OpenRouter when you explicitly want cloud inference. No cloud fallback happens automatically.
          </Typography>
        </Box>

        <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5} alignItems={{ xs: 'stretch', sm: 'center' }}>
          <Button variant="outlined" startIcon={<RefreshRoundedIcon />} onClick={handleRefreshStatus} disabled={refreshing}>
            {refreshing ? 'Refreshing...' : 'Refresh health'}
          </Button>
          <Button variant="contained" startIcon={<SaveRoundedIcon />} onClick={handleSave} disabled={saving}>
            {saving ? 'Saving...' : 'Save settings'}
          </Button>
        </Stack>
      </Stack>

      {feedback && (
        <Alert severity={feedback.type} sx={{ mb: 3 }}>
          {feedback.text}
        </Alert>
      )}

      <Paper elevation={0} sx={{ p: { xs: 2.5, md: 4 }, borderRadius: 4, mb: 4, bgcolor: 'rgba(15, 23, 42, 0.62)', backdropFilter: 'blur(14px)', border: '1px solid rgba(148, 163, 184, 0.16)' }}>
        <Stack direction={{ xs: 'column', md: 'row' }} spacing={3} alignItems={{ xs: 'stretch', md: 'center' }} justifyContent="space-between">
          <Box>
            <Typography variant="h6" sx={{ color: '#F8FAFC', fontWeight: 600 }}>Active provider</Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
              One provider and one model are selected for each investigation run.
            </Typography>
          </Box>

          <FormControl sx={{ minWidth: 260 }}>
            <InputLabel id="llm-provider-select">Provider</InputLabel>
            <Select
              labelId="llm-provider-select"
              label="Provider"
              value={selectedProvider}
              onChange={(event) => setSelectedProvider(event.target.value)}
              sx={{ bgcolor: 'rgba(255,255,255,0.03)', borderRadius: 2 }}
            >
              <MenuItem value="ollama">Ollama</MenuItem>
              <MenuItem value="gemini">Gemini</MenuItem>
              <MenuItem value="openrouter">OpenRouter</MenuItem>
            </Select>
          </FormControl>
        </Stack>

        {activeProviderStatus && (
          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5} sx={{ mt: 3, p: 2, bgcolor: 'rgba(255,255,255,0.02)', borderRadius: 2, border: '1px solid rgba(255,255,255,0.05)' }}>
            <Chip
              icon={activeProviderStatus.ok ? <CheckCircleOutlineRoundedIcon /> : <ErrorOutlineRoundedIcon />}
              label={activeProviderStatus.ok ? 'Ready for use' : 'Needs attention'}
              color={activeProviderStatus.ok ? 'success' : 'error'}
              variant="outlined"
              sx={{ fontWeight: 600 }}
            />
            <Chip label={`Model: ${activeProviderStatus.model || '—'}`} variant="outlined" sx={{ bgcolor: 'rgba(255,255,255,0.03)' }} />
            <Chip label={`Latency: ${activeProviderStatus.latency_ms ?? '—'} ms`} variant="outlined" sx={{ bgcolor: 'rgba(255,255,255,0.03)' }} />
          </Stack>
        )}
      </Paper>

      <Grid container spacing={2.5} sx={{ mb: 4 }}>
        {providerCards.map((providerCard) => {
          const providerName = providerCard.key
          const provider = providers[providerName]
          const status = providerStatus[providerName]

          return (
            <Grid item xs={12} lg={4} key={providerName}>
              <Paper elevation={0} sx={{ p: 3.5, borderRadius: 4, height: '100%', bgcolor: 'rgba(15, 23, 42, 0.4)', backdropFilter: 'blur(10px)', border: '1px solid', borderColor: selectedProvider === providerName ? 'primary.main' : 'rgba(148, 163, 184, 0.16)' }}>
                <Stack spacing={3}>
                  <Box>
                    <Stack direction="row" justifyContent="space-between" spacing={1.5} alignItems="center">
                      <Stack direction="row" spacing={1.5} alignItems="center">
                        <Box sx={{ p: 1, bgcolor: 'rgba(255,255,255,0.05)', borderRadius: 2 }}>
                          <ProviderLogo providerKey={providerName} />
                        </Box>
                        <Typography variant="h6" sx={{ fontWeight: 600, color: '#F8FAFC' }}>{providerCard.title}</Typography>
                      </Stack>
                      <Chip
                        size="small"
                        label={status?.ok ? 'Healthy' : status?.configured === false ? 'Not configured' : 'Unavailable'}
                        color={status?.ok ? 'success' : status?.configured === false ? 'default' : 'error'}
                        variant="outlined"
                        sx={{ fontWeight: 600, bgcolor: status?.ok ? 'rgba(16, 185, 129, 0.05)' : 'transparent' }}
                      />
                    </Stack>
                    <Typography variant="body2" color="text.secondary" sx={{ mt: 1.5, minHeight: 40 }}>
                      {providerCard.helper}
                    </Typography>
                  </Box>

                  {(providerName === 'ollama' || providerName === 'openrouter') && (
                    <TextField
                      label="Base URL"
                      value={provider.base_url || ''}
                      onChange={(event) => handleProviderFieldChange(providerName, 'base_url', event.target.value)}
                      fullWidth
                    />
                  )}

                  <TextField
                    label="Model"
                    value={provider.model || ''}
                    onChange={(event) => handleProviderFieldChange(providerName, 'model', event.target.value)}
                    fullWidth
                  />

                  {providerName !== 'ollama' && (
                    <TextField
                      label="API Key"
                      type="text"
                      name={`${providerName}-api-key`}
                      autoComplete="new-password"
                      value={provider.api_key || ''}
                      onChange={(event) => handleProviderFieldChange(providerName, 'api_key', event.target.value)}
                      fullWidth
                      inputProps={{
                        style: {
                          WebkitTextSecurity: 'disc',
                        },
                      }}
                      helperText={provider.has_api_key ? 'API key already stored on backend. Leave blank to keep it unchanged.' : 'API key is required before this provider can be used.'}
                    />
                  )}

                  <Box sx={{ pt: 0.5 }}>
                    <Typography variant="caption" color="text.secondary" display="block">
                      {status?.error || 'No health issues reported.'}
                    </Typography>
                  </Box>
                </Stack>
              </Paper>
            </Grid>
          )
        })}
      </Grid>

      <Paper elevation={0} sx={{ p: { xs: 2.5, md: 4 }, borderRadius: 4, bgcolor: 'rgba(245, 158, 11, 0.03)', border: '1px solid rgba(245, 158, 11, 0.2)' }}>
        <Typography variant="h6" gutterBottom sx={{ color: '#fbbf24', display: 'flex', alignItems: 'center', gap: 1 }}>
          <ErrorOutlineRoundedIcon /> Local-first policy
        </Typography>
        <Typography variant="body2" color="text.secondary">
          <b>Proceed at your own risk.</b> Cloud-based AI services expose your sensitive data to external servers and potential breaches. For absolute privacy and security, always prioritize local LLMs, which ensure your information never leaves your personal device.
        </Typography>
      </Paper>
    </Box>
  )
}

export default SettingsPage
