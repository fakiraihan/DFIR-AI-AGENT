import React, { useState, useRef } from 'react'
import axios from 'axios'
import { 
  Box, Typography, Paper, Button, Alert, CircularProgress, 
  Chip, Stack, Grid, IconButton, Divider
} from '@mui/material'
import CloudUploadIcon from '@mui/icons-material/CloudUpload'
import InsertDriveFileIcon from '@mui/icons-material/InsertDriveFile'
import CloseIcon from '@mui/icons-material/Close'
import InfoOutlinedIcon from '@mui/icons-material/InfoOutlined'
import PlayArrowIcon from '@mui/icons-material/PlayArrow'
import AssessmentIcon from '@mui/icons-material/Assessment'

const UploadPage = ({ onUploadSuccess }) => {
  const [file, setFile] = useState(null)
  const [uploading, setUploading] = useState(false)
  const [analyzing, setAnalyzing] = useState(false)
  const [analyzeResult, setAnalyzeResult] = useState(null)
  const [error, setError] = useState(null)
  const [dragActive, setDragActive] = useState(false)
  const fileInputRef = useRef(null)

  const handleDrag = (e) => {
    e.preventDefault()
    e.stopPropagation()
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true)
    } else if (e.type === 'dragleave') {
      setDragActive(false)
    }
  }

  const handleDrop = (e) => {
    e.preventDefault()
    e.stopPropagation()
    setDragActive(false)
    
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileSelect(e.dataTransfer.files[0])
    }
  }

  const handleFileSelect = (selectedFile) => {
    const allowedExtensions = ['.evtx', '.log', '.txt', '.csv']
    const fileExt = selectedFile.name.substring(selectedFile.name.lastIndexOf('.')).toLowerCase()
    
    if (!allowedExtensions.includes(fileExt)) {
      setError(`File type not supported. Allowed: ${allowedExtensions.join(', ')}`)
      return
    }
    
    setFile(selectedFile)
    setAnalyzeResult(null)
    setError(null)
  }

  const handleFileInput = (e) => {
    if (e.target.files && e.target.files[0]) {
      handleFileSelect(e.target.files[0])
    }
  }

  const handleUpload = async () => {
    if (!file) return
    
    setUploading(true)
    setError(null)
    
    const formData = new FormData()
    formData.append('file', file)
    
    try {
      // Upload file
      const uploadResponse = await axios.post('/api/upload', formData, {
        headers: {
          'Content-Type': 'multipart/form-data'
        }
      })
      
      const sessionId = uploadResponse.data.session_id
      
      // Auto-start investigation
      await axios.post(`/api/investigate/${sessionId}`)
      
      onUploadSuccess(sessionId)
    } catch (err) {
      setError(err.response?.data?.detail || 'Upload failed. Please try again.')
    } finally {
      setUploading(false)
    }
  }

  const handleQuickAnalyze = async () => {
    if (!file) return

    setAnalyzing(true)
    setError(null)
    setAnalyzeResult(null)

    const formData = new FormData()
    formData.append('file', file)
    formData.append('max_lines', '20000')
    formData.append('sample_step', '1')
    formData.append('anomaly_limit', '40')

    try {
      const response = await axios.post('/api/analyze', formData, {
        headers: {
          'Content-Type': 'multipart/form-data'
        }
      })
      setAnalyzeResult(response.data)
    } catch (err) {
      setAnalyzeResult(null)
      setError(err.response?.data?.detail || 'Quick analyze failed. Please try again.')
    } finally {
      setAnalyzing(false)
    }
  }

  const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 Bytes'
    const k = 1024
    const sizes = ['Bytes', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i]
  }

  return (
    <Box sx={{ maxWidth: 800, mx: 'auto', width: '100%', py: 4 }}>
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" gutterBottom>
          Upload Log File
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Start your forensic investigation by uploading a log file
        </Typography>
      </Box>

      <Paper 
        elevation={0}
        sx={{
          p: 4,
          mb: 4,
          border: '2px dashed',
          borderColor: dragActive ? 'primary.main' : 'divider',
          bgcolor: dragActive ? 'action.hover' : 'background.paper',
          borderRadius: 2,
          textAlign: 'center',
          cursor: 'pointer',
          transition: 'all 0.2s ease',
          '&:hover': {
            borderColor: 'primary.main',
            bgcolor: 'action.hover'
          }
        }}
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
        onClick={() => !file && fileInputRef.current?.click()}
      >
        <input
          ref={fileInputRef}
          type="file"
          onChange={handleFileInput}
          accept=".evtx,.log,.txt,.csv"
          style={{ display: 'none' }}
        />
        
        {!file ? (
          <Box sx={{ py: 3 }}>
            <CloudUploadIcon sx={{ fontSize: 64, color: 'text.secondary', mb: 2 }} />
            <Typography variant="h6" gutterBottom>
              Drop your log file here
            </Typography>
            <Typography variant="body2" color="text.secondary" gutterBottom>
              or click to browse
            </Typography>
            <Stack direction="row" spacing={1} justifyContent="center" sx={{ mt: 3 }}>
              {['.evtx', '.log', '.txt', '.csv'].map(ext => (
                <Chip key={ext} label={ext} size="small" variant="outlined" />
              ))}
            </Stack>
          </Box>
        ) : (
          <Box sx={{ display: 'flex', alignItems: 'center', p: 2, bgcolor: 'background.default', borderRadius: 1 }}>
            <InsertDriveFileIcon sx={{ fontSize: 40, color: 'primary.main', mr: 2 }} />
            <Box sx={{ flexGrow: 1, textAlign: 'left' }}>
              <Typography variant="subtitle1" noWrap sx={{ fontWeight: 600 }}>
                {file.name}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {formatFileSize(file.size)}
              </Typography>
            </Box>
            <IconButton 
              color="error" 
              onClick={(e) => {
                e.stopPropagation()
                setFile(null)
                setAnalyzeResult(null)
                setError(null)
              }}
            >
              <CloseIcon />
            </IconButton>
          </Box>
        )}
      </Paper>

      {error && (
        <Alert severity="error" sx={{ mb: 4 }}>
          {error}
        </Alert>
      )}

      <Stack direction="row" spacing={2} sx={{ mb: 4 }} justifyContent="flex-end">
        <Button 
          variant="outlined" 
          startIcon={analyzing ? <CircularProgress size={20} /> : <AssessmentIcon />}
          onClick={handleQuickAnalyze}
          disabled={!file || analyzing || uploading}
        >
          {analyzing ? 'Running Phase 1...' : 'Quick Analyze'}
        </Button>

        <Button 
          variant="contained" 
          startIcon={uploading ? <CircularProgress size={20} color="inherit" /> : <PlayArrowIcon />}
          onClick={handleUpload}
          disabled={!file || uploading || analyzing}
        >
          {uploading ? 'Starting Investigation...' : 'Start Investigation'}
        </Button>
      </Stack>

      <Paper elevation={0} sx={{ p: 3, mb: 4, bgcolor: 'background.paper', borderRadius: 2 }}>
        <Box sx={{ display: 'flex', alignItems: 'flex-start' }}>
          <InfoOutlinedIcon color="info" sx={{ mr: 2, mt: 0.5 }} />
          <Box>
            <Typography variant="subtitle1" gutterBottom sx={{ fontWeight: 600 }}>
              Investigation Pipeline
            </Typography>
            <Typography variant="body2" component="ul" sx={{ pl: 2, color: 'text.secondary' }}>
              <li>Log parsing with Drain algorithm</li>
              <li>Anomaly detection using Anomalyze Agent</li>
              <li>AI Agent investigation with threat intelligence</li>
            </Typography>
          </Box>
        </Box>
      </Paper>

      {analyzeResult && (
        <Paper elevation={0} sx={{ p: 3, mt: 4, borderRadius: 2 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
            <Typography variant="h6">Phase 1 Debug Result</Typography>
            <Chip label="/api/analyze" size="small" color="info" variant="outlined" />
          </Box>

          <Grid container spacing={2} sx={{ mb: 3 }}>
            {[
              { label: 'Parsed Lines', value: analyzeResult.summary?.parsed_lines },
              { label: 'Templates', value: analyzeResult.summary?.template_count },
              { label: 'Windows', value: analyzeResult.summary?.window_count },
              { label: 'Anomalies', value: analyzeResult.summary?.anomaly_count },
              { label: 'Strict Anomalies', value: analyzeResult.summary?.strict_anomaly_count },
              { label: 'Skipped Windows', value: analyzeResult.summary?.skipped_windows },
              { label: 'Avg Unknown Ratio', value: Number(analyzeResult.summary?.avg_unknown_ratio ?? 0).toFixed(2) },
            ].map((stat, idx) => (
              <Grid item xs={6} sm={4} md={3} key={idx}>
                <Box sx={{ p: 2, bgcolor: 'background.default', borderRadius: 1 }}>
                  <Typography variant="caption" color="text.secondary" display="block">
                    {stat.label}
                  </Typography>
                  <Typography variant="h6" sx={{ fontWeight: 600 }}>
                    {stat.value ?? 0}
                  </Typography>
                </Box>
              </Grid>
            ))}
          </Grid>

          {(analyzeResult.summary?.avg_unknown_ratio ?? 0) >= (analyzeResult.debug?.max_unknown_ratio ?? 0.4) && (
            <Alert severity="warning" sx={{ mb: 2 }}>
              High unknown template ratio detected. Parser-template mismatch may inflate anomalies.
            </Alert>
          )}

          {analyzeResult.debug?.result_truncated && (
            <Alert severity="info" sx={{ mb: 3 }}>
              Result truncated for faster debugging. Increase anomaly_limit if needed.
            </Alert>
          )}

          <Box sx={{ mt: 4 }}>
            {(analyzeResult.anomaly_results || []).slice(0, 8).map((window) => (
              <Box key={window.window_id} sx={{ mb: 3, p: 2, border: 1, borderColor: 'divider', borderRadius: 1 }}>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>
                    Window #{window.window_id}
                  </Typography>
                  <Chip 
                    label={`score ${Number(window.anomaly_score || 0).toFixed(3)}`} 
                    size="small" 
                    color="warning" 
                  />
                </Box>
                <Typography variant="caption" color="text.secondary" display="block" sx={{ mb: 2, fontFamily: 'monospace' }}>
                  actual: {window.actual_event || '-'} | predicted: {window.predicted_event || '-'}
                </Typography>
                <Stack spacing={1}>
                  {(window.lines || []).map((line) => (
                    <Box 
                      key={`${window.window_id}-${line.line_number}`}
                      sx={{ 
                        p: 1, 
                        display: 'flex', 
                        alignItems: 'flex-start',
                        bgcolor: line.is_anomalous_line ? 'rgba(239, 68, 68, 0.1)' : 'transparent',
                        borderRadius: 1,
                        borderLeft: line.is_anomalous_line ? 3 : 0,
                        borderColor: 'error.main'
                      }}
                    >
                      <Typography variant="caption" sx={{ minWidth: 40, color: 'text.secondary', fontFamily: 'monospace' }}>
                        L{line.line_number}
                      </Typography>
                      <Typography variant="body2" sx={{ flexGrow: 1, fontFamily: 'monospace', wordBreak: 'break-all' }}>
                        {line.event_template}
                      </Typography>
                      {line.is_anomalous_line && (
                        <Chip label="anomalous" size="small" color="error" variant="outlined" sx={{ height: 20, ml: 1 }} />
                      )}
                    </Box>
                  ))}
                </Stack>
              </Box>
            ))}
          </Box>
        </Paper>
      )}
    </Box>
  )
}

export default UploadPage
