import React, { useState, useRef } from 'react'
import axios from 'axios'
import { 
  Box, Typography, Paper, Button, Alert, CircularProgress, 
  Chip, Stack, Grid, IconButton, Container, Fade
} from '@mui/material'
import CloudUploadIcon from '@mui/icons-material/CloudUpload'
import InsertDriveFileIcon from '@mui/icons-material/InsertDriveFile'
import CloseIcon from '@mui/icons-material/Close'
import PlayArrowIcon from '@mui/icons-material/PlayArrow'
import AutoAwesomeIcon from '@mui/icons-material/AutoAwesome'
import KeyboardDoubleArrowRightIcon from '@mui/icons-material/KeyboardDoubleArrowRight'
import RadarIcon from '@mui/icons-material/Radar'
import SecurityIcon from '@mui/icons-material/Security'
import AssessmentIcon from '@mui/icons-material/Assessment'

const UploadPage = ({ onUploadSuccess, onStart, isLanding = true }) => {
  const [file, setFile] = useState(null)
  const [uploading, setUploading] = useState(false)
  const [analyzing, setAnalyzing] = useState(false)
  const [analyzeResult, setAnalyzeResult] = useState(null)
  const [error, setError] = useState(null)
  const [dragActive, setDragActive] = useState(false)
  const [showUpload, setShowUpload] = useState(!isLanding)
  const [isHeroExiting, setIsHeroExiting] = useState(false)
  
  const fileInputRef = useRef(null)

  const handleStart = () => {
    setIsHeroExiting(true)
    setTimeout(() => {
      setShowUpload(true)
      if (onStart) onStart()
    }, 600)
  }

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
      const uploadResponse = await axios.post('/api/upload', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      })
      
      const sessionId = uploadResponse.data.session_id
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
        headers: { 'Content-Type': 'multipart/form-data' }
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
    <Box sx={{ width: '100%', pb: 8 }}>
      {/* HERO SECTION */}
      {!showUpload && (
        <Fade in={!isHeroExiting} timeout={800} unmountOnExit>
          <Box 
            sx={{ 
              minHeight: 'calc(100vh - 48px)', 
              display: 'flex', 
              flexDirection: 'column', 
              justifyContent: 'center', 
              alignItems: 'center', 
              textAlign: 'center',
              position: 'relative',
              boxSizing: 'border-box',
              overflow: 'hidden'
            }}
          >
            {/* FLOATING BACKLIGHT BLOCKS */}
            <Box 
              sx={{
                position: 'absolute',
                top: '15%',
                left: '20%',
                width: '500px',
                height: '500px',
                background: 'radial-gradient(circle, rgba(6,182,212,0.12) 0%, rgba(0,0,0,0) 70%)',
                filter: 'blur(50px)',
                zIndex: 0,
                pointerEvents: 'none',
                animation: 'float1 14s infinite ease-in-out',
                '@keyframes float1': {
                  '0%, 100%': { transform: 'translate(0, 0) scale(1)' },
                  '50%': { transform: 'translate(40px, -40px) scale(1.15)' }
                }
              }}
            />
            <Box 
              sx={{
                position: 'absolute',
                bottom: '15%',
                right: '20%',
                width: '550px',
                height: '550px',
                background: 'radial-gradient(circle, rgba(59,130,246,0.1) 0%, rgba(0,0,0,0) 70%)',
                filter: 'blur(60px)',
                zIndex: 0,
                pointerEvents: 'none',
                animation: 'float2 18s infinite ease-in-out',
                '@keyframes float2': {
                  '0%, 100%': { transform: 'translate(0, 0) scale(1.1)' },
                  '50%': { transform: 'translate(-50px, 50px) scale(0.9)' }
                }
              }}
            />

            <Container maxWidth="md" sx={{ position: 'relative', zIndex: 1, py: 1 }}>
              {/* TOP BRAND PILL */}
              <Box 
                sx={{ 
                  display: 'inline-flex', 
                  alignItems: 'center', 
                  gap: 1.2, 
                  px: 2.2, 
                  py: 0.8, 
                  borderRadius: 5, 
                  bgcolor: 'rgba(6, 182, 212, 0.05)', 
                  border: '1px solid rgba(6, 182, 212, 0.2)', 
                  mb: 2.5,
                  boxShadow: '0 0 20px rgba(6, 182, 212, 0.05)',
                  backdropFilter: 'blur(8px)',
                  animation: 'pulseGlow 3s infinite ease-in-out',
                  '@keyframes pulseGlow': {
                    '0%, 100%': { opacity: 0.9, transform: 'scale(1)' },
                    '50%': { opacity: 1, transform: 'scale(1.02)' }
                  }
                }}
              >
                <RadarIcon sx={{ color: '#22d3ee', fontSize: 16, animation: 'spinRadar 6s linear infinite', '@keyframes spinRadar': { '100%': { transform: 'rotate(360deg)' } } }} />
                <Typography 
                  variant="caption" 
                  sx={{ 
                    color: '#22d3ee', 
                    fontWeight: 700, 
                    letterSpacing: '0.15em', 
                    textTransform: 'uppercase',
                    fontSize: '0.72rem'
                  }}
                >
                  Next-Gen DFIR Automation
                </Typography>
              </Box>

              {/* HEADING */}
              <Typography 
                variant="h2" 
                gutterBottom 
                sx={{ 
                  fontWeight: 900, 
                  color: '#F8FAFC',
                  letterSpacing: '-0.04em',
                  lineHeight: 1.15,
                  fontSize: { xs: '2.2rem', sm: '3rem', md: '3.6rem' },
                  mb: 2,
                  textShadow: '0 0 80px rgba(34, 211, 238, 0.12)'
                }}
              >
                AI-Powered <br/>
                <Box 
                  component="span" 
                  sx={{ 
                    background: 'linear-gradient(135deg, #22d3ee 10%, #3b82f6 90%)', 
                    WebkitBackgroundClip: 'text', 
                    WebkitTextFillColor: 'transparent',
                    position: 'relative'
                  }}
                >
                  Cyber Incident Investigation
                </Box>
              </Typography>

              {/* FORMAT CHIPS STACK */}
              <Stack 
                direction="row" 
                spacing={1.2} 
                justifyContent="center" 
                flexWrap="wrap" 
                useFlexGap 
                sx={{ mb: 3 }}
              >
                {[
                  { label: 'EVTX', color: '#38bdf8' },
                  { label: 'CSV', color: '#34d399' },
                  { label: 'LOG', color: '#fb7185' },
                  { label: 'TXT', color: '#a78bfa' },
                  { label: 'DeepLog', color: '#f59e0b', highlight: true },
                  { label: 'Tool-Augmented LLM', color: '#22d3ee', icon: <AutoAwesomeIcon sx={{ fontSize: '0.9rem', color: '#22d3ee' }} /> }
                ].map(tag => (
                  <Box 
                    key={tag.label} 
                    sx={{ 
                      display: 'flex', 
                      alignItems: 'center', 
                      gap: 0.8, 
                      px: 1.8, 
                      py: 0.6, 
                      borderRadius: '20px', 
                      border: tag.highlight ? '1px solid rgba(245, 158, 11, 0.4)' : '1px solid rgba(255, 255, 255, 0.08)',
                      bgcolor: tag.highlight ? 'rgba(245, 158, 11, 0.06)' : 'rgba(15, 23, 42, 0.45)',
                      boxShadow: tag.highlight ? '0 0 15px rgba(245, 158, 11, 0.1)' : '0 4px 10px rgba(0, 0, 0, 0.2)',
                      backdropFilter: 'blur(8px)',
                      transition: 'all 0.25s cubic-bezier(0.4, 0, 0.2, 1)',
                      cursor: 'default',
                      '&:hover': {
                        transform: 'translateY(-2px)',
                        borderColor: tag.color,
                        bgcolor: 'rgba(255, 255, 255, 0.03)',
                        boxShadow: `0 8px 20px rgba(0, 0, 0, 0.3), 0 0 10px ${tag.color}25`
                      }
                    }}
                  >
                    {tag.icon ? (
                      tag.icon
                    ) : (
                      <Box 
                        sx={{ 
                          width: 5, 
                          height: 5, 
                          borderRadius: '50%', 
                          bgcolor: tag.color,
                          boxShadow: `0 0 8px ${tag.color}`
                        }} 
                      />
                    )}
                    <Typography 
                      variant="body2" 
                      sx={{ 
                        fontSize: '0.78rem', 
                        fontWeight: 600, 
                        color: tag.highlight ? '#f59e0b' : '#e2e8f0',
                        letterSpacing: '0.02em'
                      }}
                    >
                      {tag.label}
                    </Typography>
                  </Box>
                ))}
              </Stack>

              {/* DESCRIPTION */}
              <Typography 
                variant="h6" 
                sx={{ 
                  maxWidth: 650, 
                  mx: 'auto', 
                  mb: 3.5,
                  color: '#94A3B8',
                  fontWeight: 400,
                  lineHeight: 1.6,
                  fontSize: { xs: '0.9rem', sm: '0.98rem' },
                  letterSpacing: '0.01em'
                }}
              >
                Automate your DFIR workflow. Upload raw security logs to instantly parse events, detect DeepLog anomalies, enrich indicators, and generate comprehensive threat reports.
              </Typography>

              {/* PIPELINE STAGES */}
              <Box sx={{ mb: 4.5, width: '100%' }}>
                <Typography 
                  variant="overline" 
                  sx={{ 
                    letterSpacing: '0.15em', 
                    fontWeight: 800, 
                    color: '#22d3ee',
                    display: 'block',
                    mb: 1.5,
                    textTransform: 'uppercase',
                    fontSize: '0.7rem',
                    opacity: 0.8
                  }}
                >
                  Investigation Pipeline
                </Typography>
                <Stack 
                  direction="row" 
                  spacing={1} 
                  alignItems="center" 
                  justifyContent="center" 
                  flexWrap="wrap" 
                  useFlexGap
                  sx={{ maxWidth: 880, mx: 'auto' }}
                >
                  {[
                    { stage: "Upload & Session", num: "01", icon: <CloudUploadIcon sx={{ fontSize: '0.9rem', color: '#22d3ee' }} /> },
                    { stage: "Parsing", num: "02", icon: <RadarIcon sx={{ fontSize: '0.9rem', color: '#38bdf8' }} /> },
                    { stage: "DeepLog Detection", num: "03", icon: <AutoAwesomeIcon sx={{ fontSize: '0.9rem', color: '#fb7185' }} /> },
                    { stage: "LLM Anomaly Gate", num: "04", icon: <SecurityIcon sx={{ fontSize: '0.9rem', color: '#34d399' }} /> },
                    { stage: "AI Agent", num: "05", icon: <AssessmentIcon sx={{ fontSize: '0.9rem', color: '#a78bfa' }} /> },
                    { stage: "Threat Intel", num: "06", icon: <RadarIcon sx={{ fontSize: '0.9rem', color: '#f59e0b' }} /> },
                    { stage: "Report Generation", num: "07", icon: <InsertDriveFileIcon sx={{ fontSize: '0.9rem', color: '#22d3ee' }} /> }
                  ].map((item, idx, arr) => (
                    <React.Fragment key={item.stage}>
                      <Box sx={{ 
                        display: 'flex',
                        alignItems: 'center',
                        gap: 1,
                        px: 1.5, 
                        py: 0.75, 
                        bgcolor: 'rgba(15, 23, 42, 0.45)', 
                        border: '1px solid rgba(6, 182, 212, 0.12)', 
                        borderRadius: '20px',
                        color: '#F8FAFC',
                        boxShadow: '0 2px 8px rgba(0, 0, 0, 0.2)',
                        transition: 'all 0.2s cubic-bezier(0.4, 0, 0.2, 1)',
                        backdropFilter: 'blur(8px)',
                        '&:hover': {
                          transform: 'translateY(-1px)',
                          borderColor: 'rgba(6, 182, 212, 0.35)',
                          boxShadow: '0 4px 12px rgba(6, 182, 212, 0.08)',
                          bgcolor: 'rgba(15, 23, 42, 0.65)',
                        }
                      }}>
                        <Box sx={{ 
                          display: 'flex', 
                          alignItems: 'center', 
                          justifyContent: 'center',
                        }}>
                          {item.icon}
                        </Box>
                        <Typography sx={{ 
                          fontWeight: 600,
                          fontSize: '0.75rem',
                          color: '#E2E8F0',
                          letterSpacing: '0.01em',
                          whiteSpace: 'nowrap'
                        }}>
                          {item.stage}
                        </Typography>
                      </Box>
                      {idx < arr.length - 1 && (
                        <KeyboardDoubleArrowRightIcon sx={{ color: 'rgba(6, 182, 212, 0.25)', fontSize: 13, mx: -0.2 }} />
                      )}
                    </React.Fragment>
                  ))}
                </Stack>
              </Box>

              {/* CALL TO ACTION */}
              <Button 
                variant="contained" 
                size="large"
                endIcon={<PlayArrowIcon />}
                onClick={handleStart}
                sx={{ 
                  py: 1.5, 
                  px: 5, 
                  fontSize: '1.05rem',
                  fontWeight: 700,
                  borderRadius: 10,
                  background: 'linear-gradient(135deg, #06b6d4 0%, #3b82f6 100%)',
                  boxShadow: '0 0 30px rgba(6, 182, 212, 0.35)',
                  transition: 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
                  letterSpacing: '0.02em',
                  '&:hover': {
                    transform: 'translateY(-2px)',
                    boxShadow: '0 0 45px rgba(6, 182, 212, 0.6)',
                    background: 'linear-gradient(135deg, #22d3ee 0%, #2563eb 100%)',
                  },
                  '&:active': {
                    transform: 'translateY(1px)'
                  }
                }}
              >
                Start Investigation
              </Button>
            </Container>
          </Box>
        </Fade>
      )}

      {/* UPLOAD SECTION */}
      {showUpload && (
        <Fade in={showUpload} timeout={800}>
          <Container maxWidth="md" sx={{ pt: 6 }}>
        <Paper 
          elevation={0}
          sx={{
            p: 5,
            mb: 4,
            border: '2px dashed',
            borderColor: dragActive ? 'primary.main' : 'rgba(6, 182, 212, 0.2)',
            bgcolor: dragActive ? 'rgba(6, 182, 212, 0.08)' : 'rgba(15, 23, 42, 0.62)',
            backdropFilter: 'blur(14px)',
            borderRadius: 4,
            textAlign: 'center',
            cursor: 'pointer',
            transition: 'all 0.3s ease',
            boxShadow: dragActive ? '0 0 40px rgba(6, 182, 212, 0.2)' : '0 24px 80px rgba(2, 8, 23, 0.45)',
            '&:hover': {
              borderColor: 'primary.main',
              bgcolor: 'rgba(6, 182, 212, 0.05)',
              boxShadow: '0 0 30px rgba(6, 182, 212, 0.15)'
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
            <Box sx={{ py: 6 }}>
              <CloudUploadIcon sx={{ fontSize: 80, color: 'primary.main', mb: 3, filter: 'drop-shadow(0 0 15px rgba(6,182,212,0.5))' }} />
              <Typography variant="h5" gutterBottom sx={{ fontWeight: 600, color: '#F8FAFC' }}>
                Drop your log file here
              </Typography>
              <Typography variant="body1" color="text.secondary">
                or click to browse from your computer
              </Typography>
            </Box>
          ) : (
            <Box sx={{ display: 'flex', alignItems: 'center', p: 4, bgcolor: 'rgba(255,255,255,0.03)', borderRadius: 3, border: '1px solid rgba(255,255,255,0.05)' }}>
              <InsertDriveFileIcon sx={{ fontSize: 56, color: 'primary.main', mr: 3 }} />
              <Box sx={{ flexGrow: 1, textAlign: 'left' }}>
                <Typography variant="h5" noWrap sx={{ fontWeight: 600, color: '#F8FAFC', mb: 0.5 }}>
                  {file.name}
                </Typography>
                <Typography variant="body1" color="text.secondary">
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
                sx={{ bgcolor: 'rgba(244, 63, 94, 0.1)', '&:hover': { bgcolor: 'rgba(244, 63, 94, 0.2)' }, p: 1.5 }}
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

        <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
          <Button 
            variant="contained" 
            color="primary"
            size="large"
            fullWidth
            startIcon={uploading ? <CircularProgress size={24} color="inherit" /> : <PlayArrowIcon />}
            onClick={handleUpload}
            disabled={!file || uploading || analyzing}
            sx={{ py: 2, fontSize: '1.1rem' }}
          >
            {uploading ? 'Starting Investigation...' : 'Start Full Investigation'}
          </Button>
          
          <Button 
            variant="outlined" 
            color="primary"
            size="large"
            fullWidth
            startIcon={analyzing ? <CircularProgress size={24} color="inherit" /> : <AssessmentIcon />}
            onClick={handleQuickAnalyze}
            disabled={!file || analyzing || uploading}
            sx={{ py: 2, fontSize: '1.1rem', bgcolor: 'rgba(15, 23, 42, 0.5)' }}
          >
            {analyzing ? 'Running Analysis...' : 'Run Quick Analysis'}
          </Button>
        </Stack>

        {analyzeResult && (
          <Paper elevation={0} sx={{ p: 4, mt: 5, borderRadius: 4, bgcolor: 'rgba(15, 23, 42, 0.62)', backdropFilter: 'blur(14px)', border: '1px solid rgba(148, 163, 184, 0.16)' }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 4 }}>
              <Typography variant="h5" sx={{ color: '#F8FAFC', fontWeight: 600 }}>Phase 1 Debug Result</Typography>
              <Chip label="/api/analyze" size="small" sx={{ bgcolor: 'rgba(6,182,212,0.1)', color: '#22d3ee', borderColor: 'rgba(6,182,212,0.3)' }} variant="outlined" />
            </Box>

            <Grid container spacing={2} sx={{ mb: 4 }}>
              {[
                { label: 'Parsed Lines', value: analyzeResult.summary?.parsed_lines },
                { label: 'Templates', value: analyzeResult.summary?.template_count },
                { label: 'Windows', value: analyzeResult.summary?.window_count },
                { label: 'Anomalies', value: analyzeResult.summary?.anomaly_count },
                { label: 'Strict Anomalies', value: analyzeResult.summary?.strict_anomaly_count },
                { label: 'Skipped Windows', value: analyzeResult.summary?.skipped_windows },
                { label: 'Avg Unknown Ratio', value: Number(analyzeResult.summary?.avg_unknown_ratio ?? 0).toFixed(2) },
              ].map((stat, idx) => (
                <Grid item xs={6} sm={4} key={idx}>
                  <Box sx={{ p: 2.5, bgcolor: 'rgba(255,255,255,0.02)', borderRadius: 3, border: '1px solid rgba(255,255,255,0.05)' }}>
                    <Typography variant="caption" color="text.secondary" display="block" sx={{ mb: 1, fontSize: '0.8rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                      {stat.label}
                    </Typography>
                    <Typography variant="h5" sx={{ fontWeight: 600, color: '#F8FAFC', lineHeight: 1 }}>
                      {stat.value ?? 0}
                    </Typography>
                  </Box>
                </Grid>
              ))}
            </Grid>

            {(analyzeResult.summary?.avg_unknown_ratio ?? 0) >= (analyzeResult.debug?.max_unknown_ratio ?? 0.4) && (
              <Alert severity="warning" sx={{ mb: 3 }}>
                High unknown template ratio detected. Parser-template mismatch may inflate anomalies.
              </Alert>
            )}

            {analyzeResult.debug?.result_truncated && (
              <Alert severity="info" sx={{ mb: 4 }}>
                Result truncated for faster debugging. Increase anomaly_limit if needed.
              </Alert>
            )}

            <Box sx={{ mt: 2 }}>
              {(analyzeResult.anomaly_results || []).slice(0, 8).map((window) => (
                <Box key={window.window_id} sx={{ mb: 3, p: 3, border: '1px solid rgba(255,255,255,0.1)', bgcolor: 'rgba(0,0,0,0.2)', borderRadius: 3 }}>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 2 }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 600, color: '#F8FAFC' }}>
                      Window #{window.window_id}
                    </Typography>
                    <Chip 
                      label={`score ${Number(window.anomaly_score || 0).toFixed(3)}`} 
                      size="small" 
                      color="warning" 
                      variant="outlined"
                    />
                  </Box>
                  <Typography variant="body2" color="text.secondary" display="block" sx={{ mb: 2.5, fontFamily: 'monospace', bgcolor: 'rgba(255,255,255,0.03)', p: 1.5, borderRadius: 2 }}>
                    actual: {window.actual_event || '-'} | predicted: {window.predicted_event || '-'}
                  </Typography>
                  <Stack spacing={1.5}>
                    {(window.lines || []).map((line) => (
                      <Box 
                        key={`${window.window_id}-${line.line_number}`}
                        sx={{ 
                          p: 1.5, 
                          display: 'flex', 
                          alignItems: 'flex-start',
                          bgcolor: line.is_anomalous_line ? 'rgba(244, 63, 94, 0.08)' : 'transparent',
                          borderRadius: 2,
                          borderLeft: line.is_anomalous_line ? '3px solid #f43f5e' : '3px solid transparent'
                        }}
                      >
                        <Typography variant="caption" sx={{ minWidth: 40, color: 'text.secondary', fontFamily: 'monospace', pt: 0.5 }}>
                          L{line.line_number}
                        </Typography>
                        <Typography variant="body2" sx={{ flexGrow: 1, fontFamily: 'monospace', wordBreak: 'break-all', color: line.is_anomalous_line ? '#fecdd3' : '#CBD5E1' }}>
                          {line.event_template}
                        </Typography>
                        {line.is_anomalous_line && (
                          <Chip label="anomalous" size="small" color="error" sx={{ height: 20, ml: 1, fontSize: '0.65rem' }} />
                        )}
                      </Box>
                    ))}
                  </Stack>
                </Box>
              ))}
            </Box>
          </Paper>
        )}
          </Container>
        </Fade>
      )}
    </Box>
  )
}

export default UploadPage
