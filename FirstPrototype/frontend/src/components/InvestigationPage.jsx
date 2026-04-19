import React, { useState, useEffect, Suspense, lazy, useRef } from 'react'
import axios from 'axios'
const MarkdownRenderer = lazy(() => import('./MarkdownRenderer'))
const PDFExportTemplate = lazy(() => import('./PDFExportTemplate'))
import ThinkingIndicator from './ThinkingIndicator'
import { 
  Box, Typography, Paper, Button, Alert, CircularProgress, 
  Chip, Stack, Grid, LinearProgress, Divider, Menu, MenuItem, ListItemIcon
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

const InvestigationPage = ({ sessionId, onBackToUpload }) => {
  const [status, setStatus] = useState(null)
  const [report, setReport] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [exportAnchorEl, setExportAnchorEl] = useState(null)
  const [isExporting, setIsExporting] = useState(false)
  const pdfExportRef = useRef(null)
  const exportMenuOpen = Boolean(exportAnchorEl)

  // Define investigation stages
  const stages = [
    { id: 'parsing', name: 'Log parsing', icon: <AssessmentIcon fontSize="small" />, description: 'Normalizing log structure and extracting records.' },
    { id: 'anomaly_detection', name: 'Anomaly detection', icon: <AnalyticsIcon fontSize="small" />, description: 'Reviewing deviation patterns across telemetry windows.' },
    { id: 'ai_agent', name: 'Correlation review', icon: <TravelExploreRoundedIcon fontSize="small" />, description: 'Linking suspicious findings into a coherent incident story.' },
    { id: 'report_generation', name: 'Report assembly', icon: <PolicyIcon fontSize="small" />, description: 'Preparing the final evidence summary.' },
    { id: 'completed', name: 'Completed', icon: <CheckCircleIcon fontSize="small" />, description: 'Investigation finished and ready for review.' }
  ]

  const currentStage = stages.find(stage => stage.id === status?.stage)
  const stageLabel = currentStage?.name || 'Investigation'
  const stageDescription = status?.current_message || currentStage?.description || 'Processing investigation results.'

  const severity = report?.metadata?.severity || (status?.status === 'error' || status?.status === 'failed' ? 'HIGH' : status?.status === 'completed' ? 'MEDIUM' : 'LOW')
  const statusLabel = status?.status ? status.status.charAt(0).toUpperCase() + status.status.slice(1) : 'Pending'
  const severityColor =
    severity === 'HIGH' ? 'error' :
    severity === 'MEDIUM' ? 'warning' :
    severity === 'LOW' ? 'info' : 'default'

  const summaryCards = [
    {
      label: 'Progress',
      value: `${Math.round(status?.progress || 0)}%`,
      tone: 'primary.main',
      helper: stageLabel,
      icon: <AnalyticsIcon fontSize="small" />,
    },
    {
      label: 'Anomalies',
      value: status?.summary?.anomalies ?? report?.ioc_analysis?.length ?? '—',
      tone: 'error.main',
      helper: status?.summary?.anomalies != null ? 'Model-detected anomalies' : report ? 'Indicators requiring review' : 'Awaiting report output',
      icon: <WarningAmberRoundedIcon fontSize="small" />,
    },
    {
      label: 'Severity',
      value: severity,
      tone: severity === 'HIGH' ? 'error.main' : severity === 'MEDIUM' ? 'warning.main' : 'info.main',
      helper: statusLabel,
      icon: <ShieldOutlinedIcon fontSize="small" />,
    },
    {
      label: 'Evidence points',
      value: report?.attack_timeline?.length ?? '—',
      tone: 'text.primary',
      helper: report ? 'Timeline events collected' : 'Pending evidence stream',
      icon: <TimelineIcon fontSize="small" />,
    },
  ]

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
        if (isActive) {
          console.error('Failed to fetch report:', err)
        }
      }
    }

    const checkStatus = async () => {
      try {
        const response = await axios.get(`/api/status/${sessionId}`)

        if (!isActive) {
          return
        }

        setStatus(response.data)

        if (response.data.status === 'completed') {
          await fetchReport()
        } else if (response.data.status === 'processing') {
          timeoutId = setTimeout(checkStatus, 1000)
        }
      } catch (err) {
        if (isActive) {
          setError(err.response?.data?.detail || 'Failed to fetch status')
        }
      } finally {
        if (isActive) {
          setLoading(false)
        }
      }
    }

    setLoading(true)
    setError(null)
    setStatus(null)
    setReport(null)
    checkStatus()

    return () => {
      isActive = false

      if (timeoutId) {
        clearTimeout(timeoutId)
      }
    }
  }, [sessionId])

  const handleExportMenuClick = (event) => {
    setExportAnchorEl(event.currentTarget)
  }

  const handleExportMenuClose = () => {
    setExportAnchorEl(null)
  }

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
      console.error('Failed to export DOCX summary:', exportError)
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
      console.error('Failed to export PDF summary:', exportError)
    } finally {
      setIsExporting(false)
    }
  }

  if (loading) {
    return (
      <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: '60vh' }}>
        <CircularProgress size={60} thickness={4} sx={{ mb: 3 }} />
        <Typography variant="h6" color="text.secondary">Loading investigation...</Typography>
      </Box>
    )
  }

  if (error) {
    return (
      <Box sx={{ maxWidth: 600, mx: 'auto', mt: 4, textAlign: 'center' }}>
        <ErrorOutlineIcon sx={{ fontSize: 80, color: 'error.main', mb: 2 }} />
        <Typography variant="h5" gutterBottom>Error Loading Investigation</Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 4 }}>{error}</Typography>
        <Button variant="contained" onClick={onBackToUpload}>Upload New File</Button>
      </Box>
    )
  }

  return (
    <Box sx={{ maxWidth: 1180, mx: 'auto', width: '100%', py: 4 }}>
      <Stack direction={{ xs: 'column', lg: 'row' }} justifyContent="space-between" spacing={3} sx={{ mb: 4 }}>
        <Box sx={{ maxWidth: 720 }}>
          <Typography variant="overline" color="primary.main">
            Investigation workspace
          </Typography>
          <Typography variant="h3" sx={{ mt: 0.75, mb: 1.25 }}>
            Detection review and evidence summary
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 2.5 }}>
            Review investigation progress, anomaly evidence, and incident recommendations in a cleaner analyst-oriented layout.
          </Typography>
          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.25}>
            <Chip label={statusLabel} color={getStatusChipColor(status?.status)} variant="outlined" />
            <Chip label={`Session ${sessionId}`} variant="outlined" sx={{ fontFamily: 'monospace' }} />
          </Stack>
        </Box>

        <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5} alignItems={{ xs: 'stretch', sm: 'center' }}>
          <Button 
            variant="outlined" 
            startIcon={<ArrowOutwardRoundedIcon />} 
            endIcon={<KeyboardArrowDownIcon />}
            onClick={handleExportMenuClick} 
            disabled={!report || isExporting}
          >
            {isExporting ? 'Exporting...' : 'Export'}
          </Button>
          <Menu
            anchorEl={exportAnchorEl}
            open={exportMenuOpen}
            onClose={handleExportMenuClose}
            anchorOrigin={{
              vertical: 'bottom',
              horizontal: 'right',
            }}
            transformOrigin={{
              vertical: 'top',
              horizontal: 'right',
            }}
          >
            <MenuItem onClick={handleExportPdf}>
              <ListItemIcon>
                <PictureAsPdfIcon fontSize="small" color="error" />
              </ListItemIcon>
              Export as PDF
            </MenuItem>
            <MenuItem onClick={handleExportDocx}>
              <ListItemIcon>
                <DescriptionIcon fontSize="small" color="info" />
              </ListItemIcon>
              Export as Word (.docx)
            </MenuItem>
          </Menu>
          <Button variant="contained" startIcon={<AddBoxIcon />} onClick={onBackToUpload}>
            New upload
          </Button>
        </Stack>
      </Stack>

      <Grid container spacing={2} sx={{ mb: 4 }}>
        {summaryCards.map((card) => (
          <Grid item xs={12} sm={6} lg={3} key={card.label}>
            <Paper elevation={0} sx={{ p: 2.5, borderRadius: 3, height: '100%', borderLeft: '2px solid', borderLeftColor: card.tone }}>
              <Stack direction="row" justifyContent="space-between" alignItems="flex-start" spacing={2}>
                <Box>
                  <Typography variant="overline" color="text.secondary">
                    {card.label}
                  </Typography>
                  <Typography variant="h4" sx={{ mt: 1, color: card.tone }}>
                    {card.value}
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                    {card.helper}
                  </Typography>
                </Box>
                <Box sx={{ color: card.tone, mt: 0.5 }}>
                  {card.icon}
                </Box>
              </Stack>
            </Paper>
          </Grid>
        ))}
      </Grid>

      {status && (
        <Paper elevation={0} sx={{ p: { xs: 2.5, md: 3 }, mb: 4, borderRadius: 3 }}>
          <Stack direction={{ xs: 'column', md: 'row' }} justifyContent="space-between" spacing={2} sx={{ mb: 3 }}>
            <Box>
              <Typography variant="h6">Investigation progress</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
                Current pipeline state, active stage, and completion progress.
              </Typography>
            </Box>
            <Chip 
              label={statusLabel}
              color={getStatusChipColor(status.status)}
              size="small"
              variant="outlined"
              sx={{ fontWeight: 'bold', alignSelf: 'flex-start' }}
            />
          </Stack>
          
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
            <Box sx={{ width: '100%', mr: 2 }}>
              <LinearProgress 
                variant="determinate" 
                value={status.progress || 0} 
                color={status.status === 'completed' ? 'success' : 'primary'}
                sx={{ height: 8, borderRadius: 4 }}
              />
            </Box>
            <Box sx={{ minWidth: 35 }}>
              <Typography variant="body2" color="text.secondary">{`${Math.round(status.progress || 0)}%`}</Typography>
            </Box>
          </Box>

          <Box sx={{ mt: 3, mb: 2.5 }}>
            <Typography variant="overline" color="text.secondary" display="block" gutterBottom>Current stage</Typography>
            <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>{stageLabel}</Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
              {stageDescription}
            </Typography>
          </Box>

          {(status.status === 'processing' || status.current_message) && (
            <ThinkingIndicator stageLabel={stageLabel} message={stageDescription} />
          )}

          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mt: 3 }}>
            {stages.map((stage, idx) => {
              const currentStageIdx = stages.findIndex(s => s.id === status.stage)
              const isActive = stage.id === status.stage
              const isCompleted = idx < currentStageIdx || status.status === 'completed'

              let color = 'default'
              if (isActive) color = 'primary'
              if (isCompleted) color = 'success'

              return (
                <Chip
                  key={stage.id}
                  icon={isCompleted ? <CheckCircleIcon /> : stage.icon}
                  label={stage.name}
                  color={color}
                  variant={isActive || isCompleted ? 'filled' : 'outlined'}
                  sx={{ 
                    opacity: isActive || isCompleted ? 1 : 0.5,
                    fontWeight: isActive ? 600 : 400
                  }}
                />
              )
            })}
          </Box>
        </Paper>
      )}

      {report && (
        <Stack spacing={4}>
          <Paper elevation={0} sx={{ p: { xs: 2.5, md: 4 }, borderRadius: 3 }}>
            <Typography variant="h6" gutterBottom>Executive summary</Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
              Consolidated report metadata and the highest-level interpretation of the session.
            </Typography>
            
            <Grid container spacing={3} sx={{ mb: 4, mt: 1 }}>
              <Grid item xs={12} sm={4}>
                <Typography variant="overline" color="text.secondary" display="block">Report ID</Typography>
                <Typography variant="body1" sx={{ fontFamily: 'monospace' }}>{report.metadata.report_id}</Typography>
              </Grid>
              <Grid item xs={12} sm={4}>
                <Typography variant="overline" color="text.secondary" display="block">Severity</Typography>
                <Chip 
                  label={report.metadata.severity} 
                  size="small"
                  color={severityColor}
                  sx={{ fontWeight: 'bold', mt: 0.5 }}
                />
              </Grid>
              <Grid item xs={12} sm={4}>
                <Typography variant="overline" color="text.secondary" display="block">Timestamp</Typography>
                <Typography variant="body2">{formatDisplayDate(report.metadata.timestamp)}</Typography>
              </Grid>
            </Grid>

            {report.executive_summary && (
              <Suspense fallback={<Typography color="text.secondary">Loading summary...</Typography>}>
                <MarkdownRenderer content={report.executive_summary} />
              </Suspense>
            )}
          </Paper>

          {report.ioc_analysis && report.ioc_analysis.length > 0 && (
            <Paper elevation={0} sx={{ p: { xs: 2.5, md: 4 }, borderRadius: 3 }}>
              <Typography variant="h6" gutterBottom>Indicators of compromise</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
                Extracted suspicious artifacts and their associated threat context.
              </Typography>
              
              <Grid container spacing={2} sx={{ mb: 4, mt: 1 }}>
                {[
                  { label: 'Total IOCs', count: report.ioc_analysis.length },
                  { label: 'Hashes', count: report.ioc_analysis.filter(ioc => ioc.type === 'md5' || ioc.type === 'sha256').length },
                  { label: 'IP Addresses', count: report.ioc_analysis.filter(ioc => ioc.type === 'ip').length },
                  { label: 'Domains', count: report.ioc_analysis.filter(ioc => ioc.type === 'domain').length }
                ].map((stat, idx) => (
                  <Grid item xs={6} sm={3} key={idx}>
                    <Box sx={{ p: 2, bgcolor: 'rgba(255,255,255,0.02)', borderRadius: 2, textAlign: 'center', border: '1px solid', borderColor: 'divider' }}>
                      <Typography variant="h4" color="primary.main">{stat.count}</Typography>
                      <Typography variant="overline" color="text.secondary">{stat.label}</Typography>
                    </Box>
                  </Grid>
                ))}
              </Grid>

              <Stack spacing={2}>
                {report.ioc_analysis.map((ioc, idx) => (
                  <Box key={idx} sx={{ p: 2.25, border: 1, borderColor: 'divider', borderRadius: 2.5, bgcolor: 'rgba(255,255,255,0.015)' }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', mb: ioc.threat_intel ? 1 : 0, flexWrap: 'wrap', gap: 1.25 }}>
                      <Chip 
                        label={ioc.type.toUpperCase()} 
                        size="small"
                        color={
                          ioc.threat_level === 'high' ? 'error' :
                          ioc.threat_level === 'medium' ? 'warning' : 'info'
                        }
                        sx={{ minWidth: 60 }}
                      />
                      <Typography variant="body2" sx={{ fontFamily: 'monospace', fontWeight: 600 }}>
                        {ioc.value}
                      </Typography>
                    </Box>
                    {ioc.threat_intel && (
                      <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                        {ioc.threat_intel}
                      </Typography>
                    )}
                  </Box>
                ))}
              </Stack>
            </Paper>
          )}

          {report.attack_timeline && report.attack_timeline.length > 0 && (
            <Paper elevation={0} sx={{ p: { xs: 2.5, md: 4 }, borderRadius: 3 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 3 }}>
                <TimelineIcon sx={{ mr: 1.5, color: 'primary.main' }} />
                <Box>
                  <Typography variant="h6">Attack timeline</Typography>
                  <Typography variant="body2" color="text.secondary">
                    Ordered event sequence showing how the incident unfolded over time.
                  </Typography>
                </Box>
              </Box>
              
              <Box sx={{ position: 'relative', pl: 3, borderLeft: 2, borderColor: 'divider', ml: 1 }}>
                {report.attack_timeline.map((event, idx) => (
                  <Box key={idx} sx={{ position: 'relative', mb: 4, '&:last-child': { mb: 0 } }}>
                    <Box sx={{ 
                      position: 'absolute', 
                      left: -33, 
                      top: 4,
                      width: 12, 
                      height: 12, 
                      borderRadius: '50%', 
                      bgcolor: 'primary.main',
                      border: '2px solid',
                      borderColor: 'background.paper'
                    }} />
                    <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 600, display: 'block', mb: 0.5 }}>
                      {formatDisplayDate(event.timestamp)}
                    </Typography>
                    <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 0.5 }}>
                      {event.event}
                    </Typography>
                    {event.details && (
                      <Typography variant="body2" color="text.secondary">
                        {event.details}
                      </Typography>
                    )}
                  </Box>
                ))}
              </Box>
            </Paper>
          )}

          {report.recommendations && report.recommendations.length > 0 && (
            <Paper elevation={0} sx={{ p: { xs: 2.5, md: 4 }, borderRadius: 3 }}>
              <Typography variant="h6" gutterBottom>Recommendations</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2.5 }}>
                Actionable next steps based on the current evidence and severity profile.
              </Typography>
              <Box component="ul" sx={{ m: 0, pl: 2 }}>
                {report.recommendations.map((rec, idx) => (
                  <Box component="li" key={idx} sx={{ mb: 1, color: 'text.secondary' }}>
                    <Suspense fallback={<Typography color="text.secondary">Loading recommendation...</Typography>}>
                      <MarkdownRenderer content={rec} />
                    </Suspense>
                  </Box>
                ))}
              </Box>
            </Paper>
          )}
        </Stack>
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
