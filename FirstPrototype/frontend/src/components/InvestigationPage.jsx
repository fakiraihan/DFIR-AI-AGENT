import React, { useState, useEffect, Suspense, lazy, useRef } from 'react'
import axios from 'axios'
const MarkdownRenderer = lazy(() => import('./MarkdownRenderer'))
const PDFExportTemplate = lazy(() => import('./PDFExportTemplate'))
import ThinkingIndicator from './ThinkingIndicator'
import { 
  Box, Typography, Paper, Button, Alert, CircularProgress, 
  Chip, Stack, Grid, LinearProgress, Divider, Menu, MenuItem, ListItemIcon,
  Stepper, Step, StepLabel, Tabs, Tab
} from '@mui/material'
import CheckCircleIcon from '@mui/icons-material/CheckCircle'
import ErrorOutlineIcon from '@mui/icons-material/ErrorOutline'
import AssessmentIcon from '@mui/icons-material/Assessment'
import PolicyIcon from '@mui/icons-material/Policy'
import AnalyticsIcon from '@mui/icons-material/Analytics'
import TimelineIcon from '@mui/icons-material/Timeline'
import AddBoxIcon from '@mui/icons-material/AddBox'
import ShieldOutlinedIcon from '@mui/icons-material/ShieldOutlined'
import WarningAmberRoundedIcon from '@mui/icons-material/WarningAmberRounded'
import TravelExploreRoundedIcon from '@mui/icons-material/TravelExploreRounded'
import ArrowOutwardRoundedIcon from '@mui/icons-material/ArrowOutwardRounded'
import PictureAsPdfIcon from '@mui/icons-material/PictureAsPdf'
import DescriptionIcon from '@mui/icons-material/Description'
import KeyboardArrowDownIcon from '@mui/icons-material/KeyboardArrowDown'
import BugReportIcon from '@mui/icons-material/BugReport'
import LightbulbIcon from '@mui/icons-material/Lightbulb'
import ArticleIcon from '@mui/icons-material/Article'

import { exportToDocx, exportToPdf } from '../utils/exportUtils'

const formatDisplayDate = (value) => {
  const parsedDate = new Date(value)
  return Number.isNaN(parsedDate.getTime()) ? 'Unavailable' : parsedDate.toLocaleString()
}

const buildExportSummary = ({ sessionId, status, report }) => {
  const exportSections = [
    '# Investigation Summary',
    '',
    `- Session ID: ${sessionId}`,
    `- Status: ${status?.status || 'unknown'}`,
    `- Progress: ${Math.round(status?.progress || 0)}%`,
    `- Stage: ${status?.stage || 'unknown'}`,
  ]

  if (report?.metadata) {
    exportSections.push(
      `- Report ID: ${report.metadata.report_id || 'Unavailable'}`,
      `- Severity: ${report.metadata.severity || 'Unavailable'}`,
      `- Generated: ${formatDisplayDate(report.metadata.timestamp)}`,
    )
  }

  if (status?.current_message) {
    exportSections.push('', '## Current status', '', status.current_message)
  }

  if (report?.executive_summary) {
    exportSections.push('', '## Executive summary', '', report.executive_summary)
  }

  if (Array.isArray(report?.ioc_analysis) && report.ioc_analysis.length > 0) {
    exportSections.push('', '## Indicators of compromise', '')
    report.ioc_analysis.forEach((ioc) => {
      const details = [ioc.type?.toUpperCase() || 'IOC', ioc.value].filter(Boolean).join(': ')
      const intel = ioc.threat_intel ? ` (${ioc.threat_intel})` : ''
      exportSections.push(`- ${details}${intel}`)
    })
  }

  if (Array.isArray(report?.attack_timeline) && report.attack_timeline.length > 0) {
    exportSections.push('', '## Attack timeline', '')
    report.attack_timeline.forEach((event) => {
      exportSections.push(`- ${formatDisplayDate(event.timestamp)} — ${event.event || 'Unknown event'}`)

      if (event.details) {
        exportSections.push(`  - ${event.details}`)
      }
    })
  }

  if (Array.isArray(report?.recommendations) && report.recommendations.length > 0) {
    exportSections.push('', '## Recommendations', '')
    report.recommendations.forEach((recommendation) => {
      exportSections.push(`- ${recommendation}`)
    })
  }

  return exportSections.join('\n')
}

const getStatusChipColor = (statusValue) => {
  if (statusValue === 'completed') return 'success'
  if (statusValue === 'error' || statusValue === 'failed') return 'error'
  if (statusValue === 'processing' || statusValue === 'skipped') return 'info'
  return 'warning'
}

const getProgressValue = (value) => {
  const numericValue = Number(value)
  if (!Number.isFinite(numericValue)) return 0
  return Math.min(100, Math.max(0, numericValue))
}

const TabPanel = (props) => {
  const { children, value, index, ...other } = props
  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`report-tabpanel-${index}`}
      aria-labelledby={`report-tab-${index}`}
      {...other}
    >
      {value === index && (
        <Box sx={{ pt: 3 }}>
          {children}
        </Box>
      )}
    </div>
  )
}

const InvestigationPage = ({ sessionId, onBackToUpload, onSessionMissing }) => {
  const [status, setStatus] = useState(null)
  const [report, setReport] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [displayProgress, setDisplayProgress] = useState(0)
  const currentProgressRef = useRef(0)
  const [exportAnchorEl, setExportAnchorEl] = useState(null)
  const [isExporting, setIsExporting] = useState(false)
  const [activeTab, setActiveTab] = useState(0)
  const pdfExportRef = useRef(null)
  const exportMenuOpen = Boolean(exportAnchorEl)

  // Mapping stages for pipeline stepper
  const pipelineStages = [
    { id: 'upload', label: 'Upload & Session', match: ['upload', 'session'] },
    { id: 'parsing', label: 'Log Parsing', match: ['parse', 'parsing'] },
    { id: 'anomaly_detection', label: 'DeepLog Detection', match: ['anomaly', 'deeplog'] },
    { id: 'llm_filter', label: 'LLM Anomaly Gate', match: ['filter', 'gate'] },
    { id: 'ai_agent', label: 'AI Agent Investigation', match: ['agent', 'investigat'] },
    { id: 'threat_intel', label: 'Threat Intel Enrichment', match: ['intel', 'enrich'] },
    { id: 'report_generation', label: 'Report Generation', match: ['report'] }
  ];

  const mapBackendStageToStep = (backendStage) => {
    if (!backendStage) return 0;
    const lowerStage = backendStage.toLowerCase();
    
    // Check if it's explicitly completed
    if (lowerStage === 'completed' || status?.status === 'completed') return pipelineStages.length;
    
    for (let i = pipelineStages.length - 1; i >= 0; i--) {
      if (pipelineStages[i].match.some(m => lowerStage.includes(m))) {
        return i;
      }
    }
    return 1; // Default to parsing if unknown but processing
  }

  const activeStep = mapBackendStageToStep(status?.stage);
  const targetProgress = getProgressValue(status?.progress)
  const severity = report?.metadata?.severity || (status?.status === 'error' || status?.status === 'failed' ? 'HIGH' : status?.status === 'completed' ? 'MEDIUM' : 'LOW')
  const statusLabel = status?.status ? status.status.charAt(0).toUpperCase() + status.status.slice(1) : 'Pending'
  
  const severityColor =
    severity === 'HIGH' ? 'error' :
    severity === 'MEDIUM' ? 'warning' :
    severity === 'LOW' ? 'info' : 'default'

  const metricCards = [
    { label: 'Parsed Logs', value: status?.summary?.parsed_logs ?? 'N/A' },
    { label: 'Templates', value: status?.summary?.templates ?? 'N/A' },
    { label: 'Anomalies', value: status?.summary?.anomalies ?? status?.summary?.anomaly_count ?? 'N/A' },
    { label: 'IOCs', value: report?.ioc_analysis?.length ?? 'N/A' }
  ];

  useEffect(() => {
    let timeoutId = null
    let isActive = true

    const fetchReport = async () => {
      try {
        const response = await axios.get(`/api/report/${sessionId}`)
        if (isActive) {
          setReport(response.data)
        }
      } catch (err) {
        if (isActive) console.error('Failed to fetch report:', err)
      }
    }

    const checkStatus = async () => {
      try {
        const response = await axios.get(`/api/status/${sessionId}`)
        if (!isActive) return

        setStatus(response.data)

        if (response.data.status === 'completed') {
          await fetchReport()
        } else if (response.data.status === 'processing') {
          timeoutId = setTimeout(checkStatus, 1500)
        }
      } catch (err) {
        if (isActive) {
          if (err.response?.status === 404 && onSessionMissing) {
            onSessionMissing()
            return
          }
          setError(err.response?.data?.detail || 'Failed to fetch status')
        }
      } finally {
        if (isActive) setLoading(false)
      }
    }

    setLoading(true)
    setError(null)
    setStatus(null)
    setReport(null)
    checkStatus()

    return () => {
      isActive = false
      if (timeoutId) clearTimeout(timeoutId)
    }
  }, [sessionId, onSessionMissing])

  useEffect(() => {
    setDisplayProgress(0)
    currentProgressRef.current = 0
  }, [sessionId])

  useEffect(() => {
    let animationFrameId;

    const animate = () => {
      const current = currentProgressRef.current;
      const dist = targetProgress - current;

      if (Math.abs(dist) < 0.2) {
        currentProgressRef.current = targetProgress;
        setDisplayProgress(targetProgress);
        return;
      }

      const step = Math.max(0.15, Math.abs(dist) * 0.08);
      currentProgressRef.current = current + Math.sign(dist) * step;
      setDisplayProgress(currentProgressRef.current);

      animationFrameId = requestAnimationFrame(animate);
    };

    animationFrameId = requestAnimationFrame(animate);

    return () => cancelAnimationFrame(animationFrameId);
  }, [targetProgress])

  const handleExportMenuClick = (event) => setExportAnchorEl(event.currentTarget)
  const handleExportMenuClose = () => setExportAnchorEl(null)

  const handleExportDocx = async () => {
    handleExportMenuClose()
    if (!report) return
    setIsExporting(true)
    try {
      const fileContents = buildExportSummary({ sessionId, status, report })
      const reportLabel = report.metadata?.report_id || sessionId
      const fileName = `${reportLabel}-summary.docx`
      await exportToDocx(fileContents, fileName)
    } catch (exportError) {
      console.error('Failed to export DOCX:', exportError)
    } finally {
      setIsExporting(false)
    }
  }

  const handleExportPdf = async () => {
    handleExportMenuClose()
    if (!report || !pdfExportRef.current) return
    setIsExporting(true)
    try {
      const reportLabel = report.metadata?.report_id || sessionId
      const fileName = `${reportLabel}-summary.pdf`
      await exportToPdf(pdfExportRef.current, fileName)
    } catch (exportError) {
      console.error('Failed to export PDF:', exportError)
    } finally {
      setIsExporting(false)
    }
  }

  if (loading) {
    return (
      <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: '60vh' }}>
        <CircularProgress size={60} thickness={4} sx={{ mb: 3 }} />
        <Typography variant="h6" color="text.secondary">Loading workspace...</Typography>
      </Box>
    )
  }

  if (error) {
    return (
      <Box sx={{ maxWidth: 600, mx: 'auto', mt: 4, textAlign: 'center' }}>
        <Alert 
          severity="error" 
          variant="filled"
          sx={{ 
            mb: 4, 
            bgcolor: 'rgba(244, 63, 94, 0.1)', 
            color: '#fecdd3', 
            border: '1px solid rgba(244, 63, 94, 0.3)',
            '& .MuiAlert-icon': { color: '#fb7185' }
          }}
        >
          {error}
        </Alert>
        <Button variant="outlined" color="primary" onClick={onBackToUpload}>Back to Upload</Button>
      </Box>
    )
  }

  return (
    <Box sx={{ maxWidth: 1200, mx: 'auto', width: '100%', py: 4 }}>
      {/* Top Summary Card */}
      <Paper elevation={0} sx={{ p: 4, mb: 4, borderRadius: 4, bgcolor: 'rgba(15, 23, 42, 0.62)', backdropFilter: 'blur(14px)', border: '1px solid rgba(148, 163, 184, 0.16)' }}>
        <Grid container spacing={3} alignItems="center" justifyContent="space-between">
          <Grid item xs={12} md={7}>
            <Typography variant="overline" sx={{ color: 'primary.main', fontWeight: 600, letterSpacing: '0.05em' }}>
              Session Active
            </Typography>
            <Typography variant="h4" sx={{ mt: 0.5, mb: 1, fontWeight: 700, color: '#F8FAFC' }}>
              {status?.status === 'completed' ? 'Investigation Complete' : 'Investigation in Progress'}
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ mb: 2, fontFamily: 'monospace' }}>
              ID: {sessionId}
            </Typography>
            <Stack direction="row" spacing={1.5} alignItems="center">
              <Chip 
                icon={status?.status === 'completed' ? <CheckCircleIcon /> : status?.status === 'error' ? <ErrorOutlineIcon /> : <CircularProgress size={14} color="inherit" />}
                label={statusLabel} 
                color={getStatusChipColor(status?.status)} 
                variant="outlined" 
                sx={{ fontWeight: 600 }}
              />
              {report?.metadata?.severity && (
                <Chip 
                  icon={<ShieldOutlinedIcon />}
                  label={`Severity: ${severity}`}
                  color={severityColor}
                  sx={{ fontWeight: 600 }}
                />
              )}
            </Stack>
          </Grid>
          
          <Grid item xs={12} md={5} sx={{ textAlign: { xs: 'left', md: 'right' } }}>
            <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5} justifyContent={{ xs: 'flex-start', md: 'flex-end' }}>
              <Button 
                variant="outlined" 
                startIcon={<ArrowOutwardRoundedIcon />} 
                endIcon={<KeyboardArrowDownIcon />}
                onClick={handleExportMenuClick} 
                disabled={!report || isExporting}
                sx={{ bgcolor: 'rgba(15, 23, 42, 0.5)' }}
              >
                {isExporting ? 'Exporting...' : 'Export Report'}
              </Button>
              <Menu
                anchorEl={exportAnchorEl}
                open={exportMenuOpen}
                onClose={handleExportMenuClose}
                PaperProps={{
                  sx: { bgcolor: 'rgba(15, 23, 42, 0.9)', backdropFilter: 'blur(10px)', border: '1px solid rgba(255,255,255,0.1)' }
                }}
              >
                <MenuItem onClick={handleExportPdf} sx={{ color: '#F8FAFC' }}>
                  <ListItemIcon><PictureAsPdfIcon fontSize="small" sx={{ color: '#f43f5e' }} /></ListItemIcon>
                  Export PDF
                </MenuItem>
                <MenuItem onClick={handleExportDocx} sx={{ color: '#F8FAFC' }}>
                  <ListItemIcon><DescriptionIcon fontSize="small" sx={{ color: '#3b82f6' }} /></ListItemIcon>
                  Export DOCX
                </MenuItem>
              </Menu>
              <Button variant="contained" startIcon={<AddBoxIcon />} onClick={onBackToUpload}>
                New Investigation
              </Button>
            </Stack>
          </Grid>
        </Grid>
      </Paper>

      {/* Progress & Stepper */}
      {status && (
        <Paper elevation={0} sx={{ p: 4, mb: 4, borderRadius: 4, bgcolor: 'rgba(15, 23, 42, 0.4)', backdropFilter: 'blur(10px)', border: '1px solid rgba(255,255,255,0.05)' }}>
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 3 }}>
            <Box sx={{ width: '100%', mr: 2 }}>
              <Box 
                sx={{
                  height: 12,
                  borderRadius: 6,
                  bgcolor: 'rgba(255,255,255,0.08)',
                  overflow: 'hidden',
                  position: 'relative'
                }}
              >
                <Box 
                  sx={{
                    position: 'absolute',
                    top: 0,
                    left: 0,
                    height: '100%',
                    width: `${Math.max(0, Math.min(100, displayProgress))}%`,
                    backgroundImage: status.status === 'completed' 
                      ? 'linear-gradient(90deg, #10b981 0%, #34d399 100%)' 
                      : status.status === 'error'
                      ? 'linear-gradient(90deg, #f43f5e 0%, #fb7185 100%)'
                      : 'linear-gradient(90deg, #6366f1 0%, #06b6d4 100%)',
                    borderRadius: 6,
                    transition: 'none', // Handled smoothly by requestAnimationFrame
                  }}
                />
              </Box>
            </Box>
            <Box sx={{ minWidth: 40, textAlign: 'right' }}>
              <Typography variant="body1" sx={{ fontWeight: 700, color: '#F8FAFC' }}>{`${Math.round(displayProgress)}%`}</Typography>
            </Box>
          </Box>

          <Stepper activeStep={activeStep} alternativeLabel sx={{ 
            display: { xs: 'none', md: 'flex' },
            '& .MuiStepConnector-line': { borderColor: 'rgba(255,255,255,0.1)' }
          }}>
            {pipelineStages.map((stage, index) => (
              <Step key={stage.id} completed={index < activeStep || status.status === 'completed'}>
                <StepLabel
                  StepIconProps={{
                    sx: {
                      color: 'rgba(255,255,255,0.1) !important',
                      '&.Mui-active': { color: '#06b6d4 !important' },
                      '&.Mui-completed': { color: '#10b981 !important' },
                      '& text': { fill: '#fff !important', fontWeight: 600 }
                    }
                  }}
                >
                  <Typography variant="caption" sx={{ color: index === activeStep ? '#F8FAFC' : 'text.secondary', fontWeight: index === activeStep ? 600 : 400 }}>
                    {stage.label}
                  </Typography>
                </StepLabel>
              </Step>
            ))}
          </Stepper>
          
          <Box sx={{ mt: 3, p: 2, bgcolor: 'rgba(255,255,255,0.02)', borderRadius: 2, border: '1px solid rgba(255,255,255,0.05)' }}>
             <Typography variant="caption" color="text.secondary" display="block" sx={{ textTransform: 'uppercase', letterSpacing: '0.05em', mb: 0.5 }}>Current Message</Typography>
             <Typography variant="body2" sx={{ color: '#F8FAFC', fontWeight: 500 }}>{status.current_message || 'Processing...'}</Typography>
          </Box>
        </Paper>
      )}

      {/* Metrics Overview */}
      {(status?.summary || report) && (
        <Grid container spacing={2} sx={{ mb: 4 }}>
          {metricCards.map((card, idx) => (
            card.value !== 'N/A' && (
              <Grid item xs={6} sm={3} key={idx}>
                <Paper elevation={0} sx={{ p: 3, borderRadius: 3, textAlign: 'center', bgcolor: 'rgba(15, 23, 42, 0.62)', backdropFilter: 'blur(10px)', border: '1px solid rgba(255,255,255,0.05)' }}>
                  <Typography variant="h3" sx={{ color: 'primary.main', fontWeight: 700, mb: 0.5 }}>{card.value}</Typography>
                  <Typography variant="overline" color="text.secondary" sx={{ letterSpacing: '0.05em' }}>{card.label}</Typography>
                </Paper>
              </Grid>
            )
          ))}
        </Grid>
      )}

      {/* Report Section */}
      {status?.status === 'completed' && report && (
        <Paper elevation={0} sx={{ borderRadius: 4, bgcolor: 'rgba(15, 23, 42, 0.62)', backdropFilter: 'blur(14px)', border: '1px solid rgba(148, 163, 184, 0.16)', overflow: 'hidden' }}>
          <Box sx={{ borderBottom: 1, borderColor: 'divider', bgcolor: 'rgba(0,0,0,0.2)' }}>
            <Tabs 
              value={activeTab} 
              onChange={(e, newValue) => setActiveTab(newValue)} 
              variant="scrollable" 
              scrollButtons="auto"
              sx={{ 
                '& .MuiTab-root': { color: 'text.secondary', fontWeight: 600, py: 2.5 },
                '& .Mui-selected': { color: 'primary.main' }
              }}
            >
              <Tab icon={<ArticleIcon sx={{ mb: 0 }}/>} iconPosition="start" label="Overview" />
              <Tab icon={<BugReportIcon sx={{ mb: 0 }}/>} iconPosition="start" label="IOCs" disabled={!report.ioc_analysis || report.ioc_analysis.length === 0} />
              <Tab icon={<TimelineIcon sx={{ mb: 0 }}/>} iconPosition="start" label="Timeline" disabled={!report.attack_timeline || report.attack_timeline.length === 0} />
              <Tab icon={<LightbulbIcon sx={{ mb: 0 }}/>} iconPosition="start" label="Recommendations" disabled={!report.recommendations || report.recommendations.length === 0} />
            </Tabs>
          </Box>

          <Box sx={{ p: { xs: 3, md: 5 } }}>
            <TabPanel value={activeTab} index={0}>
              <Typography variant="h5" sx={{ mb: 3, fontWeight: 700, color: '#F8FAFC' }}>Executive Summary</Typography>
              {report.executive_summary ? (
                <Suspense fallback={<Typography color="text.secondary">Loading summary...</Typography>}>
                  <MarkdownRenderer content={report.executive_summary} />
                </Suspense>
              ) : (
                <Typography color="text.secondary">No executive summary available.</Typography>
              )}
            </TabPanel>

            <TabPanel value={activeTab} index={1}>
              <Typography variant="h5" sx={{ mb: 3, fontWeight: 700, color: '#F8FAFC' }}>Indicators of Compromise</Typography>
              <Stack spacing={2}>
                {(report.ioc_analysis || []).map((ioc, idx) => (
                  <Box key={idx} sx={{ p: 2.5, border: '1px solid rgba(255,255,255,0.1)', borderRadius: 3, bgcolor: 'rgba(255,255,255,0.02)' }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', mb: ioc.threat_intel ? 1.5 : 0, flexWrap: 'wrap', gap: 1.5 }}>
                      <Chip 
                        label={ioc.type?.toUpperCase()} 
                        size="small"
                        color={ioc.threat_level === 'high' ? 'error' : ioc.threat_level === 'medium' ? 'warning' : 'info'}
                        sx={{ fontWeight: 700 }}
                      />
                      <Typography variant="body1" sx={{ fontFamily: 'monospace', fontWeight: 600, color: '#F8FAFC' }}>
                        {ioc.value}
                      </Typography>
                    </Box>
                    {ioc.threat_intel && (
                      <Typography variant="body2" color="text.secondary" sx={{ p: 1.5, bgcolor: 'rgba(0,0,0,0.2)', borderRadius: 2 }}>
                        {ioc.threat_intel}
                      </Typography>
                    )}
                  </Box>
                ))}
              </Stack>
            </TabPanel>

            <TabPanel value={activeTab} index={2}>
              <Typography variant="h5" sx={{ mb: 4, fontWeight: 700, color: '#F8FAFC' }}>Attack Timeline</Typography>
              <Box sx={{ position: 'relative', pl: 3.5, borderLeft: '2px solid rgba(6, 182, 212, 0.3)', ml: 1 }}>
                {(report.attack_timeline || []).map((event, idx) => (
                  <Box key={idx} sx={{ position: 'relative', mb: 5, '&:last-child': { mb: 0 } }}>
                    <Box sx={{ 
                      position: 'absolute', 
                      left: -37, 
                      top: 4,
                      width: 14, 
                      height: 14, 
                      borderRadius: '50%', 
                      bgcolor: '#06b6d4',
                      border: '3px solid #0f172a',
                      boxShadow: '0 0 10px rgba(6,182,212,0.5)'
                    }} />
                    <Typography variant="caption" sx={{ color: 'primary.main', fontWeight: 700, display: 'block', mb: 1, letterSpacing: '0.05em' }}>
                      {formatDisplayDate(event.timestamp)}
                    </Typography>
                    <Typography variant="h6" sx={{ fontWeight: 600, mb: 1, color: '#F8FAFC', lineHeight: 1.3 }}>
                      {event.event}
                    </Typography>
                    {event.details && (
                      <Typography variant="body2" color="text.secondary" sx={{ bgcolor: 'rgba(255,255,255,0.02)', p: 2, borderRadius: 2, border: '1px solid rgba(255,255,255,0.05)' }}>
                        {event.details}
                      </Typography>
                    )}
                  </Box>
                ))}
              </Box>
            </TabPanel>

            <TabPanel value={activeTab} index={3}>
              <Typography variant="h5" sx={{ mb: 3, fontWeight: 700, color: '#F8FAFC' }}>Recommendations</Typography>
              <Box component="ul" sx={{ m: 0, pl: 0, listStyle: 'none' }}>
                {(report.recommendations || []).map((rec, idx) => (
                  <Box component="li" key={idx} sx={{ mb: 2 }}>
                    <Paper elevation={0} sx={{ p: 2.5, bgcolor: 'rgba(16, 185, 129, 0.05)', border: '1px solid rgba(16, 185, 129, 0.2)', borderRadius: 3 }}>
                      <Suspense fallback={<Typography color="text.secondary">Loading recommendation...</Typography>}>
                        <MarkdownRenderer content={rec} />
                      </Suspense>
                    </Paper>
                  </Box>
                ))}
              </Box>
            </TabPanel>
          </Box>
        </Paper>
      )}

      {/* Hidden export template for PDF generation */}
      {report && (
        <Box sx={{ position: 'absolute', top: '-9999px', left: '-9999px', width: '0', height: '0', overflow: 'hidden' }}>
          <Box ref={pdfExportRef}>
            <Suspense fallback={<div />}>
              <PDFExportTemplate 
                content={buildExportSummary({ sessionId, status, report })} 
                metadata={{ sessionId: report.metadata?.report_id || sessionId }}
              />
            </Suspense>
          </Box>
        </Box>
      )}
    </Box>
  )
}

export default InvestigationPage
