import React, { useState, useEffect, Suspense, lazy, useRef } from 'react'
import axios from 'axios'
const PDFExportTemplate = lazy(() => import('./PDFExportTemplate'))
import { 
  Box, Typography, Paper, Button, Alert, CircularProgress, 
  Chip, Stack, Grid, Menu, MenuItem, ListItemIcon,
  Stepper, Step, StepLabel
} from '@mui/material'
import CheckCircleIcon from '@mui/icons-material/CheckCircle'
import ErrorOutlineIcon from '@mui/icons-material/ErrorOutline'
import AddBoxIcon from '@mui/icons-material/AddBox'
import ShieldOutlinedIcon from '@mui/icons-material/ShieldOutlined'
import ArrowOutwardRoundedIcon from '@mui/icons-material/ArrowOutwardRounded'
import PictureAsPdfIcon from '@mui/icons-material/PictureAsPdf'
import DescriptionIcon from '@mui/icons-material/Description'
import KeyboardArrowDownIcon from '@mui/icons-material/KeyboardArrowDown'
import TableChartIcon from '@mui/icons-material/TableChart'
import DataObjectIcon from '@mui/icons-material/DataObject'
import CloudUploadOutlinedIcon from '@mui/icons-material/CloudUploadOutlined'
import FactCheckOutlinedIcon from '@mui/icons-material/FactCheckOutlined'
import ReportDashboard from './ReportDashboard'

import { PDF_EXPORT_WIDTH_PX, exportToDocx, exportToPdf, saveFile } from '../utils/exportUtils'

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
      exportSections.push(`- ${formatDisplayDate(event.timestamp)}: ${event.event || 'Unknown event'}`)

      if (event.details) {
        exportSections.push(`  - ${event.details}`)
      }
    })
  }

  if (Array.isArray(report?.recommendations) && report.recommendations.length > 0) {
    exportSections.push('', '## Recommendations', '')
    report.recommendations.forEach((recommendation, index) => {
      exportSections.push(`${index + 1}. ${recommendation}`)
    })
  }

  return exportSections.join('\n')
}

const asArray = (value) => (Array.isArray(value) ? value : [])

const compactText = (value, fallback = 'Not available') => {
  if (value === null || value === undefined || value === '') return fallback
  return String(value).replace(/\s+/g, ' ').trim() || fallback
}

const markdownCell = (value) => compactText(value).replace(/\|/g, '\\|')

const pushTable = (sections, headers, rows) => {
  if (!rows.length) return
  sections.push(`| ${headers.join(' | ')} |`)
  sections.push(`| ${headers.map(() => '---').join(' | ')} |`)
  rows.forEach((row) => {
    sections.push(`| ${row.map(markdownCell).join(' | ')} |`)
  })
  sections.push('')
}

const buildExportSummaryV2 = ({ sessionId, status, report }) => {
  const metadata = report?.metadata || {}
  const caseOverview = report?.case_overview || {}
  const detection = report?.detection_analysis || {}
  const methodology = report?.methodology || {}
  const impact = report?.impact_assessment || {}
  const confidence = report?.limitations_confidence || {}
  const evidenceItems = asArray(report?.evidence_provenance?.items)
  const logEvidence = evidenceItems.filter((item) => item.type === 'log_window')
  const toolEvidence = evidenceItems.filter((item) => item.type === 'tool_result')
  const findings = asArray(detection.findings)
  const strongestIndicators = asArray(detection.strongest_compromise_indicators)
  const iocs = asArray(report?.ioc_analysis)
  const recommendations = asArray(report?.recommendations)
  const timeline = asArray(report?.appendices?.timeline).length
    ? asArray(report?.appendices?.timeline)
    : asArray(report?.attack_timeline)
  const mitreTechniques = asArray(report?.mitre_attack_mapping?.techniques)
  const limitations = asArray(confidence.limitations)
  const components = asArray(methodology.tools).join(', ') || 'Drain, DeepLog, LLM anomaly gate, DFIR agent, report generator'
  const alertSummary = [
    `${detection.anomaly_count ?? asArray(report?.attack_timeline).length ?? 0} anomaly windows`,
    `${detection.ioc_count ?? iocs.length} curated IOCs`,
    `${detection.tool_result_count ?? toolEvidence.length} threat-intel results`,
    `${mitreTechniques.length} ATT&CK mappings`,
  ].join('; ')

  const exportSections = [
    '# 3. Detection and Analysis',
    '',
    `- Session ID: ${sessionId}`,
    `- Report ID: ${metadata.report_id || 'Unavailable'}`,
    `- Case Status: ${caseOverview.case_status || 'Not assessed'}`,
    `- Generated: ${formatDisplayDate(metadata.timestamp || caseOverview.generated_at)}`,
    `- Workflow Status: ${status?.status || 'unknown'}`,
    '',
  ]

  exportSections.push('## 3.1 Detection Overview', '')
  pushTable(exportSections, ['Field', 'Value'], [
    ['Waktu deteksi', formatDisplayDate(metadata.timestamp || caseOverview.generated_at)],
    ['Sumber log', caseOverview.log_file || metadata.log_file],
    ['Komponen deteksi', components],
    ['Ringkasan alert/anomali', alertSummary],
    ['Basis penilaian', caseOverview.assessment_basis || 'Generated from available investigation evidence.'],
  ])

  if (report?.executive_summary) {
    exportSections.push('### Executive Summary', '', report.executive_summary, '')
  }

  exportSections.push('## 3.2 Anomaly Details', '')
  if (strongestIndicators.length) {
    pushTable(exportSections, ['Indicator', 'Category', 'Strength', 'Reason', 'Evidence'], strongestIndicators.map((item) => [
      item.indicator,
      item.category,
      item.strength,
      item.reason,
      asArray(item.evidence_ids).join(', '),
    ]))
  }
  if (logEvidence.length || findings.length) {
    pushTable(exportSections, ['Evidence ID', 'Event/template', 'Parameter penting', 'Host/user/process', 'Relevance'], (
      logEvidence.length ? logEvidence : findings
    ).slice(0, 15).map((item, index) => {
      const relatedFinding = findings[index] || {}
      return [
        item.evidence_id || relatedFinding.finding_id,
        item.description || relatedFinding.title,
        relatedFinding.detail || item.reference,
        'Not available in the current report payload',
        item.reference || asArray(relatedFinding.evidence_ids).join(', '),
      ]
    }))
  } else {
    exportSections.push('Tidak ada anomaly detail terstruktur pada payload report.', '')
  }

  exportSections.push('## 3.3 Evidence Collection', '')
  pushTable(exportSections, ['Evidence type', 'Evidence collected', 'Reference'], [
    ['Log evidence', `${logEvidence.length} anomalous log-window evidence item(s)`, logEvidence.map((item) => item.evidence_id).join(', ') || 'Not available'],
    ['IOC evidence', `${iocs.length} curated IOC(s)`, iocs.slice(0, 8).map((ioc) => ioc.indicator || ioc.value).join(', ') || 'Not available'],
    ['Process/network evidence', findings.map((finding) => finding.title).join('; ') || 'Not available'],
    ['Threat intelligence evidence', `${toolEvidence.length} enrichment evidence item(s)`, toolEvidence.map((item) => item.evidence_id).join(', ') || 'Not available'],
  ])

  if (evidenceItems.length > 0) {
    pushTable(exportSections, ['ID', 'Type', 'Reference', 'Description'], evidenceItems.slice(0, 25).map((item) => [
      item.evidence_id,
      item.type,
      item.reference,
      item.description,
    ]))
  }

  exportSections.push('## 3.4 Timeline Reconstruction', '')
  if (timeline.length) {
    pushTable(exportSections, ['Time', 'Event', 'Details', 'Evidence'], timeline.slice(0, 20).map((event) => [
      formatDisplayDate(event.timestamp),
      event.event || event.event_template,
      event.details || event.description,
      event.evidence_id || event.evidence_reference,
    ]))
  } else {
    exportSections.push('Timeline belum tersedia atau timestamp tidak cukup untuk rekonstruksi kronologis.', '')
  }

  exportSections.push('## 3.5 IOC and Threat Intelligence Correlation', '')
  if (iocs.length) {
    pushTable(exportSections, ['Indicator', 'Type', 'Reputation result', 'Interpretation'], iocs.slice(0, 25).map((ioc) => [
      ioc.indicator || ioc.value,
      ioc.indicator_type || ioc.type,
      ioc.threat_intel,
      ioc.threat_level ? `Threat level: ${ioc.threat_level}` : 'Requires analyst validation',
    ]))
  } else {
    exportSections.push('Tidak ada IOC terkurasi yang tersedia pada report.', '')
  }

  if (toolEvidence.length) {
    pushTable(exportSections, ['Tool evidence', 'Target', 'Result'], toolEvidence.slice(0, 20).map((item) => [
      item.evidence_id,
      item.reference,
      item.description,
    ]))
  }

  exportSections.push('## 3.6 Scope and Impact Analysis', '')
  pushTable(exportSections, ['Scope / impact field', 'Assessment'], [
    ['Host terdampak', 'Not assessed from current report payload'],
    ['User terdampak', 'Not assessed from current report payload'],
    ['Business impact', impact.business_impact],
    ['Operational impact', impact.operational_impact],
    ['Data exposure', impact.data_exposure],
    ['Service disruption', impact.service_disruption],
    ['Recoverability', impact.recoverability],
  ])

  if (limitations.length > 0) {
    exportSections.push('### Keterbatasan Analisis', '')
    limitations.forEach((limitation) => exportSections.push(`- ${limitation}`))
    exportSections.push('')
  }

  exportSections.push('## 3.7 Severity, Confidence, and Classification', '')
  pushTable(exportSections, ['Classification field', 'Value'], [
    ['Jenis insiden', mitreTechniques.length ? mitreTechniques.map((item) => item.tactic).join(', ') : report?.mitre_attack_mapping?.status || 'Not assessed'],
    ['Severity', metadata.severity || caseOverview.severity || 'Not assessed'],
    ['Confidence', confidence.confidence_level || 'Low'],
    ['Dasar penilaian', caseOverview.assessment_basis || alertSummary],
  ])

  if (mitreTechniques.length) {
    pushTable(exportSections, ['Technique', 'Tactic', 'Confidence', 'Rationale'], mitreTechniques.map((technique) => [
      `${technique.technique_id || '-'} ${technique.technique_name || ''}`.trim(),
      technique.tactic,
      technique.confidence,
      technique.rationale,
    ]))
  }

  exportSections.push('## 3.8 Detection and Analysis Conclusion', '')
  exportSections.push(
    `Berdasarkan report ini, analisis mendeteksi ${alertSummary}. Severity diklasifikasikan sebagai ${metadata.severity || caseOverview.severity || 'Not assessed'} dengan confidence ${confidence.confidence_level || 'Low'}. Kesimpulan tetap dibatasi pada evidence yang tersedia dan perlu divalidasi dengan telemetry host, EDR, SIEM, DNS/proxy, serta konteks asset inventory sebelum containment berskala besar.`,
    '',
  )

  if (recommendations.length) {
    exportSections.push('### Initial Containment / Response Recommendations', '')
    recommendations.slice(0, 10).forEach((recommendation, index) => {
      exportSections.push(`${index + 1}. ${compactText(recommendation)}`)
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

const formatAgentEventTime = (value) => {
  const parsedDate = new Date(value)
  if (Number.isNaN(parsedDate.getTime())) return '--:--:--'

  return parsedDate.toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  })
}

const getAgentStageLabel = (stage) => {
  const labels = {
    pending: 'QUEUE',
    parsing: 'PARSER',
    anomaly_detection: 'DEEPLOG',
    ai_agent: 'AGENT',
    report_generation: 'REPORT',
    completed: 'DONE',
  }

  return labels[stage] || String(stage || 'SYSTEM').replace(/_/g, ' ').toUpperCase()
}

const getAgentEventLine = (event) => event?.line || event?.message || 'Agent activity update received.'

const getAgentEventColor = (level) => {
  if (level === 'success') return '#86efac'
  if (level === 'warning') return '#fbbf24'
  if (level === 'error') return '#fb7185'
  if (level === 'stage') return '#bfdbfe'
  if (level === 'status') return '#c4b5fd'
  return '#CBD5E1'
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
  const pdfExportRef = useRef(null)
  const exportMenuOpen = Boolean(exportAnchorEl)

  // Mapping stages for pipeline stepper
  const pipelineStages = [
    { id: 'upload', label: 'Upload & Session', match: ['upload', 'session'] },
    { id: 'parsing', label: 'Log Parsing', match: ['parse', 'parsing'] },
    { id: 'anomaly_detection', label: 'DeepLog Detection', match: ['anomaly', 'deeplog'] },
    { id: 'ai_agent', label: 'JejakAgent Investigation', match: ['agent', 'investigat', 'triage'] },
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

  const activityEvents = Array.isArray(status?.activity_events) ? status.activity_events : []
  const latestAgentEvent = activityEvents[activityEvents.length - 1]
  const shouldShowAgentTerminal = Boolean(status && status.status !== 'completed' && !report)
  const liveInvestigationStats = [
    { label: 'Anomaly windows', value: status?.summary?.anomalies ?? status?.summary?.anomaly_count ?? 'Pending', tone: '#bfdbfe' },
    { label: 'Curated IOCs', value: status?.summary?.iocs ?? status?.summary?.ioc_count ?? 'Pending', tone: '#93c5fd' },
    { label: 'Evidence items', value: status?.summary?.evidence_items ?? status?.summary?.evidence_count ?? 'Pending', tone: '#fcd34d' },
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
      const fileContents = buildExportSummaryV2({ sessionId, status, report })
      const reportLabel = report.metadata?.report_id || sessionId
      const fileName = `${reportLabel}-summary.docx`
      await exportToDocx(fileContents, fileName)
    } catch (exportError) {
      console.error('Failed to export DOCX:', exportError)
      window.alert(`DOCX export failed: ${exportError?.message || 'Unknown export error'}`)
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

  const handleExportParsedLogs = async (format) => {
    handleExportMenuClose()
    if (!sessionId) return
    setIsExporting(true)
    try {
      const response = await axios.get(`/api/export/${sessionId}`, {
        params: { format },
        responseType: 'blob',
      })
      const fallbackNames = {
        jsonl: `${sessionId}-parsed-logs.jsonl`,
        ndjson: `${sessionId}-elastic-bulk.ndjson`,
        csv: `${sessionId}-parsed-logs.csv`,
        manifest: `${sessionId}-export-manifest.json`,
      }
      const acceptTypeMap = {
        jsonl: {
          description: 'JSON Lines',
          accept: { 'application/x-ndjson': ['.jsonl'] },
        },
        ndjson: {
          description: 'NDJSON',
          accept: { 'application/x-ndjson': ['.ndjson'] },
        },
        csv: {
          description: 'CSV',
          accept: { 'text/csv': ['.csv'] },
        },
        manifest: {
          description: 'JSON',
          accept: { 'application/json': ['.json'] },
        },
      }

      const contentDisposition = response.headers?.['content-disposition'] || ''
      const fileNameMatch = contentDisposition.match(/filename="?([^"]+)"?/i)
      const fileName = fileNameMatch?.[1] || fallbackNames[format] || `${sessionId}-export.dat`

      await saveFile(response.data, fileName, acceptTypeMap[format] || {
        description: 'File',
        accept: { 'application/octet-stream': ['.*'] }
      })
    } catch (exportError) {
      console.error(`Failed to export parsed logs (${format}):`, exportError)
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
      <Paper elevation={0} sx={{ p: 4, mb: 4, borderRadius: 2, bgcolor: 'rgba(15, 23, 42, 0.84)', border: '1px solid rgba(148, 163, 184, 0.16)' }}>
        <Grid container spacing={3} alignItems="center" justifyContent="space-between">
          <Grid item xs={12} md={7}>
            <Typography variant="overline" sx={{ color: 'primary.main', fontWeight: 600, letterSpacing: 0 }}>
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
                disabled={isExporting || (!report && status?.status !== 'completed')}
                sx={{ bgcolor: 'rgba(15, 23, 42, 0.5)' }}
              >
                {isExporting ? 'Exporting...' : 'Export Report'}
              </Button>
              <Menu
                anchorEl={exportAnchorEl}
                open={exportMenuOpen}
                onClose={handleExportMenuClose}
                PaperProps={{
                  sx: { bgcolor: 'rgba(15, 23, 42, 0.96)', border: '1px solid rgba(255,255,255,0.1)' }
                }}
              >
                <MenuItem onClick={handleExportPdf} disabled={!report} sx={{ color: '#F8FAFC' }}>
                  <ListItemIcon><PictureAsPdfIcon fontSize="small" sx={{ color: '#f43f5e' }} /></ListItemIcon>
                  Export PDF
                </MenuItem>
                <MenuItem onClick={handleExportDocx} disabled={!report} sx={{ color: '#F8FAFC' }}>
                  <ListItemIcon><DescriptionIcon fontSize="small" sx={{ color: '#3b82f6' }} /></ListItemIcon>
                  Export DOCX
                </MenuItem>
                <MenuItem onClick={() => handleExportParsedLogs('jsonl')} sx={{ color: '#F8FAFC' }}>
                  <ListItemIcon><DataObjectIcon fontSize="small" sx={{ color: '#bfdbfe' }} /></ListItemIcon>
                  Export Parsed JSONL
                </MenuItem>
                <MenuItem onClick={() => handleExportParsedLogs('ndjson')} sx={{ color: '#F8FAFC' }}>
                  <ListItemIcon><CloudUploadOutlinedIcon fontSize="small" sx={{ color: '#93c5fd' }} /></ListItemIcon>
                  Export Elastic NDJSON
                </MenuItem>
                <MenuItem onClick={() => handleExportParsedLogs('csv')} sx={{ color: '#F8FAFC' }}>
                  <ListItemIcon><TableChartIcon fontSize="small" sx={{ color: '#f59e0b' }} /></ListItemIcon>
                  Export Parsed CSV
                </MenuItem>
                <MenuItem onClick={() => handleExportParsedLogs('manifest')} sx={{ color: '#F8FAFC' }}>
                  <ListItemIcon><FactCheckOutlinedIcon fontSize="small" sx={{ color: '#c4b5fd' }} /></ListItemIcon>
                  Download Export Manifest
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
        <Paper elevation={0} sx={{ p: 4, mb: 4, borderRadius: 2, bgcolor: 'rgba(15, 23, 42, 0.72)', border: '1px solid rgba(255,255,255,0.08)' }}>
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
                    backgroundImage: 'none',
                    backgroundColor: status.status === 'completed' 
                      ? '#2563eb' 
                      : status.status === 'error'
                      ? '#be123c'
                      : '#2563eb',
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
                      '&.Mui-active': { color: '#2563eb !important' },
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
          
          {shouldShowAgentTerminal && (
            <Grid container spacing={2} sx={{ mt: 3 }}>
              {liveInvestigationStats.map((card) => (
                <Grid item xs={12} sm={4} key={card.label}>
                  <Paper
                    elevation={0}
                    sx={{
                      p: 2.25,
                      minHeight: 104,
                      borderRadius: 2,
                      bgcolor: 'rgba(2, 6, 23, 0.48)',
                      border: '1px solid rgba(148, 163, 184, 0.14)',
                    }}
                  >
                    <Typography sx={{ color: card.tone, fontWeight: 900, fontSize: { xs: '1.45rem', md: '1.85rem' }, lineHeight: 1 }}>
                      {card.value}
                    </Typography>
                    <Typography variant="overline" sx={{ color: '#94A3B8', letterSpacing: 0 }}>
                      {card.label}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          )}

          {shouldShowAgentTerminal && (
          <Paper
            elevation={0}
            sx={{
              mt: 3,
              overflow: 'hidden',
              borderRadius: 2,
              border: '1px solid rgba(148, 163, 184, 0.16)',
              bgcolor: 'rgba(2, 6, 23, 0.86)',
              boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.04)',
              position: 'relative',
              '&::before': {
                content: '""',
                position: 'absolute',
                inset: 0,
                pointerEvents: 'none',
                backgroundImage: 'linear-gradient(rgba(148, 163, 184, 0.032) 1px, transparent 1px)',
                backgroundSize: '100% 11px',
                opacity: 0.24,
              },
            }}
          >
            <Box sx={{ position: 'relative', zIndex: 1 }}>
              <Box
                sx={{
                  px: 2.5,
                  py: 1.4,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: 2,
                  borderBottom: '1px solid rgba(148, 163, 184, 0.14)',
                  bgcolor: 'rgba(15, 23, 42, 0.72)',
                }}
              >
                <Stack direction="row" spacing={1.2} alignItems="center">
                  <Stack direction="row" spacing={0.7}>
                    <Box sx={{ width: 9, height: 9, borderRadius: '50%', bgcolor: '#fb7185' }} />
                    <Box sx={{ width: 9, height: 9, borderRadius: '50%', bgcolor: '#f59e0b' }} />
                    <Box sx={{ width: 9, height: 9, borderRadius: '50%', bgcolor: '#93c5fd' }} />
                  </Stack>
                  <Typography sx={{ color: '#bfdbfe', fontFamily: 'monospace', fontWeight: 800, letterSpacing: 0, fontSize: '0.78rem' }}>
                    AGENT_TERMINAL
                  </Typography>
                </Stack>
                <Chip
                  size="small"
                  label={status.status === 'completed' ? 'SESSION CLOSED' : 'LIVE TRACE'}
                  sx={{
                    height: 22,
                    color: status.status === 'completed' ? '#bbf7d0' : '#bfdbfe',
                    border: '1px solid rgba(147,197,253,0.26)',
                    bgcolor: 'rgba(37, 99, 235, 0.14)',
                    fontFamily: 'monospace',
                    fontWeight: 700,
                    letterSpacing: 0,
                  }}
                />
              </Box>

              <Box sx={{ p: { xs: 2, md: 2.5 } }}>
                <Box sx={{ mb: 2.2, display: 'flex', alignItems: 'center', gap: 1.2, flexWrap: 'wrap' }}>
                  <Typography sx={{ color: '#bfdbfe', fontFamily: 'monospace', fontWeight: 800 }}>$</Typography>
                  <Typography sx={{ color: '#E2E8F0', fontFamily: 'monospace', fontSize: '0.88rem' }}>
                    run dfir-agent --session {sessionId} --observe
                  </Typography>
                  {latestAgentEvent && (
                    <Chip
                      size="small"
                      label={`${Math.round(getProgressValue(latestAgentEvent.progress))}%`}
                      sx={{ height: 22, color: '#f8fafc', bgcolor: '#2563eb', fontFamily: 'monospace', fontWeight: 900 }}
                    />
                  )}
                </Box>

                <Box
                  sx={{
                    minHeight: { xs: 180, md: 220 },
                    maxHeight: { xs: 280, md: 340 },
                    overflowY: 'auto',
                    display: 'block',
                    px: 1.35,
                    py: 1.2,
                    borderRadius: 2,
                    bgcolor: 'rgba(15, 23, 42, 0.58)',
                    border: '1px solid rgba(148, 163, 184, 0.16)',
                    boxShadow: 'none',
                    scrollbarWidth: 'thin',
                    scrollbarColor: 'rgba(147,197,253,0.38) rgba(15,23,42,0.4)',
                    '&::-webkit-scrollbar': { width: 8 },
                    '&::-webkit-scrollbar-thumb': { bgcolor: 'rgba(147,197,253,0.3)', borderRadius: 999 },
                    '&::-webkit-scrollbar-track': { bgcolor: 'rgba(15,23,42,0.42)' },
                    animation: 'agentLineFade 0.45s ease-out both',
                    '@keyframes agentLineFade': {
                      '0%': { opacity: 0.72, transform: 'translateY(4px)' },
                      '18%': { opacity: 1, transform: 'translateY(0)' },
                      '78%': { opacity: 1, transform: 'translateY(0)' },
                      '100%': { opacity: 0.74, transform: 'translateY(-1px)' },
                    },
                  }}
                >
                  {latestAgentEvent ? (
                    <Stack spacing={1.05}>
                      {activityEvents.slice(-10, -1).map((event, index) => (
                        <Box
                          key={event.sequence || event.timestamp || `${event.stage}-${index}`}
                          sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', md: '84px 96px minmax(0, 1fr)' }, gap: { xs: 0.35, md: 1.25 }, alignItems: 'start', width: '100%' }}
                        >
                          <Typography sx={{ color: '#64748b', fontFamily: 'monospace', fontSize: '0.76rem' }}>
                            {formatAgentEventTime(event.timestamp)}
                          </Typography>
                          <Typography sx={{ color: '#bfdbfe', fontFamily: 'monospace', fontWeight: 900, fontSize: '0.74rem', letterSpacing: 0 }}>
                            [{getAgentStageLabel(event.stage)}]
                          </Typography>
                          <Typography sx={{ color: getAgentEventColor(event.level), fontFamily: 'monospace', fontSize: '0.82rem', lineHeight: 1.55, whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>
                            <Box component="span" sx={{ color: '#93c5fd', mr: 1 }}>{'>'}</Box>
                            {getAgentEventLine(event).replace(/\s+/g, ' ')}
                          </Typography>
                        </Box>
                      ))}
                    <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', md: '84px 96px minmax(0, 1fr)' }, gap: { xs: 0.35, md: 1.25 }, alignItems: 'start', width: '100%' }}>
                      <Typography sx={{ color: '#64748b', fontFamily: 'monospace', fontSize: '0.76rem' }}>
                        {formatAgentEventTime(latestAgentEvent.timestamp)}
                      </Typography>
                      <Typography sx={{ color: '#bfdbfe', fontFamily: 'monospace', fontWeight: 900, fontSize: '0.74rem', letterSpacing: 0 }}>
                        [{getAgentStageLabel(latestAgentEvent.stage)}]
                      </Typography>
                      <Typography sx={{ color: getAgentEventColor(latestAgentEvent.level), fontFamily: 'monospace', fontSize: '0.82rem', lineHeight: 1.55, whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>
                        <Box component="span" sx={{ color: '#93c5fd', mr: 1 }}>›</Box>
                        {getAgentEventLine(latestAgentEvent).replace(/\s+/g, ' ')}
                      </Typography>
                    </Box>
                    </Stack>
                  ) : (
                    <Typography sx={{ color: '#94A3B8', fontFamily: 'monospace', fontSize: '0.85rem' }}>
                      › Waiting for agent telemetry stream...
                    </Typography>
                  )}
                </Box>
              </Box>
            </Box>
          </Paper>
          )}
        </Paper>
      )}

      {/* Report Section */}
      {status?.status === 'completed' && report && (
        <ReportDashboard report={report} formatDisplayDate={formatDisplayDate} />
      )}

      {/* Hidden export template for printable PDF/DOCX generation */}
      {report && (
        <Box sx={{ position: 'absolute', top: 0, left: '-12000px', width: `${PDF_EXPORT_WIDTH_PX}px`, minHeight: '1200px', overflow: 'visible', pointerEvents: 'none', opacity: 0 }}>
          <Box ref={pdfExportRef}>
            <Suspense fallback={<div />}>
              <PDFExportTemplate
                content={buildExportSummaryV2({ sessionId, status, report })}
                metadata={{
                  sessionId: report.metadata?.session_id || sessionId,
                  reportId: report.metadata?.report_id,
                  severity: report.metadata?.severity,
                  logFile: report.metadata?.log_file,
                }}
              />
            </Suspense>
          </Box>
        </Box>
      )}
    </Box>
  )
}

export default InvestigationPage
