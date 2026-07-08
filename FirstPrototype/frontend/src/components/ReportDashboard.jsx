import React, { Suspense, lazy, useMemo, useState } from 'react'
import {
  Box,
  Chip,
  Divider,
  Grid,
  Paper,
  Stack,
  Tab,
  Tabs,
  Typography,
} from '@mui/material'
import ArticleIcon from '@mui/icons-material/Article'
import BugReportIcon from '@mui/icons-material/BugReport'
import FactCheckOutlinedIcon from '@mui/icons-material/FactCheckOutlined'
import GppMaybeOutlinedIcon from '@mui/icons-material/GppMaybeOutlined'
import Inventory2OutlinedIcon from '@mui/icons-material/Inventory2Outlined'
import LightbulbIcon from '@mui/icons-material/Lightbulb'
import RouteOutlinedIcon from '@mui/icons-material/RouteOutlined'
import SecurityIcon from '@mui/icons-material/Security'
import TimelineIcon from '@mui/icons-material/Timeline'

const MarkdownRenderer = lazy(() => import('./MarkdownRenderer'))

const asArray = (value) => (Array.isArray(value) ? value : [])

const displayValue = (value, fallback = 'Not available') => {
  if (value === null || value === undefined || value === '') return fallback
  return String(value)
}

const severitySx = (severity) => {
  if (severity === 'HIGH' || severity === 'CRITICAL') {
    return { color: '#fecdd3', borderColor: 'rgba(244, 63, 94, 0.38)', bgcolor: 'rgba(244, 63, 94, 0.1)' }
  }
  if (severity === 'MEDIUM') {
    return { color: '#fde68a', borderColor: 'rgba(245, 158, 11, 0.38)', bgcolor: 'rgba(245, 158, 11, 0.1)' }
  }
  return { color: '#bfdbfe', borderColor: 'rgba(59, 130, 246, 0.34)', bgcolor: 'rgba(59, 130, 246, 0.1)' }
}

const TabPanel = ({ children, value, index }) => (
  <Box
    role="tabpanel"
    hidden={value !== index}
    id={`report-v2-tabpanel-${index}`}
    aria-labelledby={`report-v2-tab-${index}`}
  >
    {value === index && <Box sx={{ pt: 3 }}>{children}</Box>}
  </Box>
)

const Panel = ({ children, sx }) => (
  <Paper
    elevation={0}
    sx={{
      p: { xs: 2, md: 2.5 },
      borderRadius: 2,
      bgcolor: 'rgba(15, 23, 42, 0.72)',
      border: '1px solid rgba(148, 163, 184, 0.16)',
      minWidth: 0,
      maxWidth: '100%',
      overflow: 'hidden',
      ...sx,
    }}
  >
    {children}
  </Paper>
)

const SectionTitle = ({ icon, title, kicker }) => (
  <Stack direction="row" spacing={1.4} alignItems="center" sx={{ mb: 2.2 }}>
    <Box sx={{ color: '#bfdbfe', display: 'flex' }}>{icon}</Box>
    <Box sx={{ minWidth: 0 }}>
      <Typography variant="overline" sx={{ color: '#94A3B8', letterSpacing: 0 }}>
        {kicker}
      </Typography>
      <Typography variant="h6" sx={{ color: '#F8FAFC', fontWeight: 800, lineHeight: 1.2, overflowWrap: 'anywhere' }}>
        {title}
      </Typography>
    </Box>
  </Stack>
)

const StatTile = ({ label, value, tone = '#bfdbfe' }) => (
  <Panel sx={{ minHeight: 112 }}>
    <Typography sx={{ color: tone, fontWeight: 900, fontSize: { xs: '1.65rem', md: '2.05rem' }, lineHeight: 1 }}>
      {displayValue(value, '0')}
    </Typography>
    <Typography variant="overline" sx={{ color: '#94A3B8', letterSpacing: 0 }}>
      {label}
    </Typography>
  </Panel>
)

const DetailRow = ({ label, value }) => (
  <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', sm: '180px minmax(0, 1fr)' }, gap: 1, py: 1.2, minWidth: 0 }}>
    <Typography variant="body2" sx={{ color: '#94A3B8', fontWeight: 700 }}>
      {label}
    </Typography>
    <Typography variant="body2" sx={{ color: '#E2E8F0', minWidth: 0, overflowWrap: 'anywhere', wordBreak: 'break-word' }}>
      {displayValue(value)}
    </Typography>
  </Box>
)

const EmptyState = ({ label }) => (
  <Panel sx={{ borderStyle: 'dashed', bgcolor: 'rgba(15, 23, 42, 0.36)' }}>
    <Typography variant="body2" sx={{ color: '#94A3B8' }}>
      {label}
    </Typography>
  </Panel>
)

const ReportDashboard = ({ report, formatDisplayDate }) => {
  const [activeTab, setActiveTab] = useState(0)

  const evidenceItems = asArray(report?.evidence_provenance?.items)
  const detectionFindings = asArray(report?.detection_analysis?.findings)
  const strongestIndicators = asArray(report?.detection_analysis?.strongest_compromise_indicators)
  const mitreTechniques = asArray(report?.mitre_attack_mapping?.techniques)
  const iocs = asArray(report?.ioc_analysis)
  const timeline = asArray(report?.appendices?.timeline).length
    ? asArray(report?.appendices?.timeline)
    : asArray(report?.attack_timeline)
  const recommendations = asArray(report?.recommendations)
  const limitations = asArray(report?.limitations_confidence?.limitations)

  const topStats = useMemo(() => ([
    { label: 'Anomaly windows', value: report?.detection_analysis?.anomaly_count ?? report?.attack_timeline?.length ?? 0, tone: '#bfdbfe' },
    { label: 'Curated IOCs', value: report?.detection_analysis?.ioc_count ?? iocs.length, tone: '#93c5fd' },
    { label: 'Evidence items', value: evidenceItems.length, tone: '#fcd34d' },
  ]), [evidenceItems.length, iocs.length, report])

  return (
    <Box sx={{ display: 'grid', gap: 3 }}>
      <Grid container spacing={2}>
        {topStats.map((item) => (
          <Grid item xs={12} sm={4} key={item.label}>
            <StatTile {...item} />
          </Grid>
        ))}
      </Grid>

      <Box sx={{ borderRadius: 2, border: '1px solid rgba(148, 163, 184, 0.16)', overflow: 'hidden', bgcolor: 'rgba(15, 23, 42, 0.5)' }}>
        <Box sx={{ borderBottom: '1px solid rgba(148, 163, 184, 0.14)', bgcolor: 'rgba(2, 6, 23, 0.5)' }}>
          <Tabs
            value={activeTab}
            onChange={(event, value) => setActiveTab(value)}
            variant="scrollable"
            scrollButtons="auto"
            sx={{
              minHeight: 58,
              '& .MuiTab-root': { minHeight: 58, color: '#94A3B8', fontWeight: 800 },
              '& .Mui-selected': { color: '#bfdbfe' },
              '& .MuiTabs-indicator': { bgcolor: '#2563eb', height: 3 },
            }}
          >
            <Tab icon={<ArticleIcon sx={{ mb: 0 }} />} iconPosition="start" label="Overview" />
            <Tab icon={<FactCheckOutlinedIcon sx={{ mb: 0 }} />} iconPosition="start" label="Evidence" />
            <Tab icon={<BugReportIcon sx={{ mb: 0 }} />} iconPosition="start" label="Detection" />
            <Tab icon={<SecurityIcon sx={{ mb: 0 }} />} iconPosition="start" label="MITRE" />
            <Tab icon={<GppMaybeOutlinedIcon sx={{ mb: 0 }} />} iconPosition="start" label="Impact" />
            <Tab icon={<Inventory2OutlinedIcon sx={{ mb: 0 }} />} iconPosition="start" label="Appendix" />
          </Tabs>
        </Box>

        <Box sx={{ p: { xs: 2, md: 3 } }}>
          <TabPanel value={activeTab} index={0}>
            <Grid container spacing={2.5}>
              <Grid item xs={12} md={7}>
                <Stack spacing={2}>
                  <Panel>
                    <SectionTitle icon={<ArticleIcon />} kicker="Case" title="Overview" />
                    <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap sx={{ mb: 1 }}>
                      <Chip size="small" label={displayValue(report?.case_overview?.case_status, 'Case status unavailable')} sx={{ color: '#E2E8F0', border: '1px solid rgba(226, 232, 240, 0.2)', bgcolor: 'rgba(226, 232, 240, 0.05)' }} />
                      <Chip size="small" label={`Confidence: ${displayValue(report?.limitations_confidence?.confidence_level, 'Low')}`} sx={{ color: '#fde68a', border: '1px solid rgba(245, 158, 11, 0.28)', bgcolor: 'rgba(245, 158, 11, 0.08)' }} />
                    </Stack>
                    <DetailRow label="Severity" value={report?.metadata?.severity} />
                    <Divider sx={{ borderColor: 'rgba(148, 163, 184, 0.12)' }} />
                    <DetailRow label="Generated" value={formatDisplayDate(report?.metadata?.timestamp || report?.case_overview?.generated_at)} />
                    <Divider sx={{ borderColor: 'rgba(148, 163, 184, 0.12)' }} />
                    <DetailRow label="Log file" value={report?.case_overview?.log_file || report?.metadata?.log_file} />
                    <Divider sx={{ borderColor: 'rgba(148, 163, 184, 0.12)' }} />
                    <DetailRow label="Assessment basis" value={report?.case_overview?.assessment_basis || 'Generated from the available investigation state.'} />
                  </Panel>
                  <Panel>
                    <SectionTitle icon={<ArticleIcon />} kicker="Narrative" title="Executive Summary" />
                    {report?.executive_summary ? (
                      <Suspense fallback={<Typography color="text.secondary">Loading summary...</Typography>}>
                        <MarkdownRenderer content={report.executive_summary} />
                      </Suspense>
                    ) : (
                      <Typography color="text.secondary">No executive summary available.</Typography>
                    )}
                  </Panel>
                </Stack>
              </Grid>
              <Grid item xs={12} md={5}>
                <Stack spacing={2}>
                  <Panel>
                    <SectionTitle icon={<LightbulbIcon />} kicker="Action" title="Priority Recommendations" />
                    {recommendations.length ? (
                      <Stack spacing={1.5}>
                        {recommendations.slice(0, 5).map((item, index) => (
                          <Box key={`${item}-${index}`} sx={{ display: 'grid', gridTemplateColumns: '30px minmax(0, 1fr)', gap: 1.2, alignItems: 'start', width: '100%', minWidth: 0 }}>
                            <Chip size="small" label={index + 1} sx={{ height: 24, minWidth: 24, bgcolor: 'rgba(37, 99, 235, 0.16)', color: '#bfdbfe', fontWeight: 900 }} />
                            <Box sx={{ minWidth: 0, maxWidth: '100%' }}>
                              <Suspense fallback={<Typography color="text.secondary">Loading...</Typography>}>
                                <MarkdownRenderer content={item} />
                              </Suspense>
                            </Box>
                          </Box>
                        ))}
                      </Stack>
                    ) : <Typography color="text.secondary">No recommendations available.</Typography>}
                  </Panel>
                  <Panel>
                    <SectionTitle icon={<RouteOutlinedIcon />} kicker="Scope" title="Objectives" />
                    <Stack spacing={1}>
                      {asArray(report?.objectives_scope?.objectives).map((objective, index) => (
                        <Typography key={`${objective}-${index}`} variant="body2" sx={{ color: '#E2E8F0' }}>
                          {index + 1}. {objective}
                        </Typography>
                      ))}
                    </Stack>
                  </Panel>
                </Stack>
              </Grid>
            </Grid>
          </TabPanel>

          <TabPanel value={activeTab} index={1}>
            <SectionTitle icon={<FactCheckOutlinedIcon />} kicker="Provenance" title="Evidence Register" />
            {evidenceItems.length ? (
              <Grid container spacing={2}>
                {evidenceItems.map((item) => (
                  <Grid item xs={12} md={6} key={item.evidence_id}>
                    <Panel>
                      <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap sx={{ mb: 1.5 }}>
                        <Chip size="small" label={item.evidence_id} sx={{ bgcolor: 'rgba(37, 99, 235, 0.14)', color: '#bfdbfe', fontWeight: 900 }} />
                        <Chip size="small" label={displayValue(item.type)} variant="outlined" sx={{ color: '#CBD5E1', borderColor: 'rgba(203, 213, 225, 0.24)' }} />
                      </Stack>
                      <Typography variant="body2" sx={{ color: '#F8FAFC', mb: 1 }}>
                        {displayValue(item.description)}
                      </Typography>
                      <DetailRow label="Reference" value={item.reference} />
                      <DetailRow label="Timestamp" value={item.timestamp} />
                    </Panel>
                  </Grid>
                ))}
              </Grid>
            ) : <EmptyState label="No evidence items are available for this report." />}
          </TabPanel>

          <TabPanel value={activeTab} index={2}>
            <Grid container spacing={2.5}>
              <Grid item xs={12} lg={7}>
                <SectionTitle icon={<BugReportIcon />} kicker="Findings" title="Detection Analysis" />
                <Stack spacing={2}>
                  {strongestIndicators.length ? (
                    <Panel sx={{ borderColor: 'rgba(251, 191, 36, 0.24)', bgcolor: 'rgba(69, 26, 3, 0.14)' }}>
                      <Typography variant="subtitle2" sx={{ color: '#FDE68A', fontWeight: 900, mb: 1.4 }}>
                        Strongest Compromise Indicators
                      </Typography>
                      <Stack spacing={1.4}>
                        {strongestIndicators.map((item, index) => (
                          <Box key={`${item.indicator}-${index}`} sx={{ display: 'grid', gridTemplateColumns: '28px minmax(0, 1fr)', gap: 1.2 }}>
                            <Chip size="small" label={index + 1} sx={{ height: 24, minWidth: 24, bgcolor: 'rgba(251, 191, 36, 0.18)', color: '#FDE68A', fontWeight: 900 }} />
                            <Box sx={{ minWidth: 0 }}>
                              <Stack direction="row" spacing={0.8} flexWrap="wrap" useFlexGap sx={{ mb: 0.6 }}>
                                <Chip size="small" label={displayValue(item.strength, 'medium')} sx={severitySx(item.strength === 'high' ? 'HIGH' : 'MEDIUM')} />
                                <Chip size="small" label={displayValue(item.category, 'indicator')} variant="outlined" sx={{ color: '#E2E8F0', borderColor: 'rgba(226, 232, 240, 0.22)' }} />
                              </Stack>
                              <Typography sx={{ color: '#F8FAFC', fontFamily: 'monospace', fontWeight: 800, overflowWrap: 'anywhere' }}>
                                {displayValue(item.indicator)}
                              </Typography>
                              <Typography variant="body2" sx={{ color: '#FDE68A', mt: 0.6 }}>
                                {displayValue(item.reason)}
                              </Typography>
                              <Stack direction="row" spacing={0.8} flexWrap="wrap" useFlexGap sx={{ mt: 0.8 }}>
                                {asArray(item.evidence_ids).map((id) => (
                                  <Chip key={id} size="small" label={id} variant="outlined" sx={{ color: '#bfdbfe', borderColor: 'rgba(147, 197, 253, 0.26)' }} />
                                ))}
                              </Stack>
                            </Box>
                          </Box>
                        ))}
                      </Stack>
                    </Panel>
                  ) : null}
                  {detectionFindings.length ? detectionFindings.map((finding) => (
                    <Panel key={finding.finding_id}>
                      <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap sx={{ mb: 1.2 }}>
                        <Chip size="small" label={finding.finding_id} sx={{ bgcolor: 'rgba(196, 181, 253, 0.14)', color: '#c4b5fd', fontWeight: 900 }} />
                        <Typography variant="subtitle1" sx={{ color: '#F8FAFC', fontWeight: 800 }}>
                          {displayValue(finding.title, 'Finding')}
                        </Typography>
                      </Stack>
                      <Typography variant="body2" sx={{ color: '#CBD5E1', mb: 1.4 }}>
                        {displayValue(finding.detail)}
                      </Typography>
                      <Stack direction="row" spacing={0.8} flexWrap="wrap" useFlexGap>
                        {asArray(finding.evidence_ids).map((id) => (
                          <Chip key={id} size="small" label={id} variant="outlined" sx={{ color: '#bfdbfe', borderColor: 'rgba(147, 197, 253, 0.26)' }} />
                        ))}
                      </Stack>
                    </Panel>
                  )) : <EmptyState label="No detection findings are available." />}
                </Stack>
              </Grid>
              <Grid item xs={12} lg={5}>
                <SectionTitle icon={<TimelineIcon />} kicker="Sequence" title="Incident Timeline" />
                <Stack spacing={1.5}>
                  {timeline.length ? timeline.map((event, index) => (
                    <Panel key={`${event.timestamp}-${event.event}-${index}`}>
                      <Typography variant="caption" sx={{ color: '#bfdbfe', fontWeight: 800 }}>
                        {formatDisplayDate(event.timestamp)}
                      </Typography>
                      <Typography variant="subtitle2" sx={{ color: '#F8FAFC', fontWeight: 800, mt: 0.5 }}>
                        {displayValue(event.event, event.event_template || 'Anomalous event')}
                      </Typography>
                      <Typography variant="body2" sx={{ color: '#CBD5E1', mt: 0.8 }}>
                        {displayValue(event.details || event.description)}
                      </Typography>
                      {event.evidence_id && (
                        <Chip size="small" label={event.evidence_id} sx={{ mt: 1.2, bgcolor: 'rgba(37, 99, 235, 0.14)', color: '#bfdbfe' }} />
                      )}
                    </Panel>
                  )) : <EmptyState label="No timeline events are available." />}
                </Stack>
              </Grid>
            </Grid>
          </TabPanel>

          <TabPanel value={activeTab} index={3}>
            <SectionTitle icon={<SecurityIcon />} kicker="Technique Mapping" title="MITRE ATT&CK" />
            <Panel sx={{ mb: 2 }}>
              <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
                <Chip size="small" label={`Status: ${displayValue(report?.mitre_attack_mapping?.status)}`} sx={{ bgcolor: 'rgba(37, 99, 235, 0.14)', color: '#bfdbfe', fontWeight: 800 }} />
                {asArray(report?.mitre_attack_mapping?.tactics).map((tactic) => (
                  <Chip key={tactic} size="small" label={tactic} variant="outlined" sx={{ color: '#E2E8F0', borderColor: 'rgba(226, 232, 240, 0.22)' }} />
                ))}
              </Stack>
            </Panel>
            {mitreTechniques.length ? (
              <Grid container spacing={2}>
                {mitreTechniques.map((technique) => (
                  <Grid item xs={12} md={6} key={technique.technique_id}>
                    <Panel>
                      <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap sx={{ mb: 1.2 }}>
                        <Chip size="small" label={technique.technique_id} sx={{ bgcolor: 'rgba(244, 114, 182, 0.14)', color: '#f9a8d4', fontWeight: 900 }} />
                        <Chip size="small" label={displayValue(technique.confidence)} sx={{ ...severitySx(technique.confidence === 'high' ? 'HIGH' : 'LOW'), textTransform: 'uppercase' }} />
                      </Stack>
                      <Typography variant="subtitle1" sx={{ color: '#F8FAFC', fontWeight: 900 }}>
                        {displayValue(technique.technique_name)}
                      </Typography>
                      <Typography variant="body2" sx={{ color: '#94A3B8', mb: 1 }}>
                        {displayValue(technique.tactic)}
                      </Typography>
                      <Typography variant="body2" sx={{ color: '#CBD5E1' }}>
                        {displayValue(technique.rationale)}
                      </Typography>
                    </Panel>
                  </Grid>
                ))}
              </Grid>
            ) : <EmptyState label="No supported ATT&CK mapping was produced from the available evidence." />}
          </TabPanel>

          <TabPanel value={activeTab} index={4}>
            <Grid container spacing={2.5}>
              <Grid item xs={12} md={6}>
                <SectionTitle icon={<GppMaybeOutlinedIcon />} kicker="Risk" title="Impact Assessment" />
                <Panel>
                  {Object.entries(report?.impact_assessment || {}).map(([key, value], index) => (
                    <React.Fragment key={key}>
                      {index > 0 && <Divider sx={{ borderColor: 'rgba(148, 163, 184, 0.12)' }} />}
                      <DetailRow label={key.replace(/_/g, ' ')} value={value} />
                    </React.Fragment>
                  ))}
                </Panel>
              </Grid>
              <Grid item xs={12} md={6}>
                <SectionTitle icon={<GppMaybeOutlinedIcon />} kicker="Confidence" title="Limitations" />
                {limitations.length ? (
                  <Stack spacing={1.5}>
                    {limitations.map((item, index) => (
                      <Panel key={`${item}-${index}`} sx={{ borderColor: 'rgba(245, 158, 11, 0.2)', bgcolor: 'rgba(69, 26, 3, 0.16)' }}>
                        <Typography variant="body2" sx={{ color: '#FDE68A' }}>
                          {item}
                        </Typography>
                      </Panel>
                    ))}
                  </Stack>
                ) : <EmptyState label="No limitations were recorded." />}
              </Grid>
            </Grid>
          </TabPanel>

          <TabPanel value={activeTab} index={5}>
            <Grid container spacing={2.5}>
              <Grid item xs={12} lg={6}>
                <SectionTitle icon={<Inventory2OutlinedIcon />} kicker="IOC Table" title="Curated Indicators" />
                <Stack spacing={1.5}>
                  {iocs.length ? iocs.map((ioc, index) => (
                    <Panel key={`${ioc.value}-${index}`}>
                      <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap sx={{ mb: 1 }}>
                        <Chip size="small" label={displayValue(ioc.type, 'IOC').toUpperCase()} sx={{ bgcolor: 'rgba(37, 99, 235, 0.14)', color: '#bfdbfe', fontWeight: 900 }} />
                        <Chip size="small" label={displayValue(ioc.threat_level, 'unknown')} sx={severitySx(ioc.threat_level === 'high' ? 'HIGH' : ioc.threat_level === 'medium' ? 'MEDIUM' : 'LOW')} />
                      </Stack>
                      <Typography sx={{ color: '#F8FAFC', fontFamily: 'monospace', fontWeight: 800, wordBreak: 'break-word' }}>
                        {displayValue(ioc.indicator || ioc.value)}
                      </Typography>
                      <Typography variant="body2" sx={{ color: '#CBD5E1', mt: 1 }}>
                        {displayValue(ioc.threat_intel)}
                      </Typography>
                    </Panel>
                  )) : <EmptyState label="No curated IOC entries are available." />}
                </Stack>
              </Grid>
              <Grid item xs={12} lg={6}>
                <SectionTitle icon={<RouteOutlinedIcon />} kicker="Method" title="Methodology" />
                <Panel>
                  <DetailRow label="Validation" value={report?.methodology?.validation_status} />
                  <Divider sx={{ borderColor: 'rgba(148, 163, 184, 0.12)', my: 1 }} />
                  <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap sx={{ mb: 2 }}>
                    {asArray(report?.methodology?.tools).map((tool) => (
                      <Chip key={tool} size="small" label={tool} variant="outlined" sx={{ color: '#E2E8F0', borderColor: 'rgba(226,232,240,0.2)' }} />
                    ))}
                  </Stack>
                  <Stack spacing={1}>
                    {asArray(report?.methodology?.steps_performed).map((step, index) => (
                      <Typography key={`${step.step}-${index}`} variant="body2" sx={{ color: '#CBD5E1' }}>
                        {index + 1}. {displayValue(step.step)}
                      </Typography>
                    ))}
                  </Stack>
                </Panel>
              </Grid>
            </Grid>
          </TabPanel>
        </Box>
      </Box>
    </Box>
  )
}

export default ReportDashboard
