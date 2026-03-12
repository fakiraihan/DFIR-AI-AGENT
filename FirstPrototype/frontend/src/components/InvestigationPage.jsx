import React, { useState, useEffect } from 'react'
import './InvestigationPage.css'
import './ThinkingIndicator.css'
import axios from 'axios'
import ThinkingIndicator from './ThinkingIndicator'

const InvestigationPage = ({ sessionId, onBackToUpload, onOpenChatbot }) => {
  const [status, setStatus] = useState(null)
  const [report, setReport] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  // Define investigation stages
  const stages = [
    { id: 'parsing', name: 'Log Parsing', icon: '📝', description: 'Menganalisis struktur log' },
    { id: 'anomaly_detection', name: 'Anomaly Detection', icon: '🔍', description: 'Deteksi anomali dengan DeepLog' },
    { id: 'ai_agent', name: 'AI Investigation', icon: '🤖', description: 'AI Agent sedang bekerja' },
    { id: 'report_generation', name: 'Report Generation', icon: '📄', description: 'Menyusun laporan' },
    { id: 'completed', name: 'Completed', icon: '✓', description: 'Investigasi selesai' }
  ]

  useEffect(() => {
    const checkStatus = async () => {
      try {
        const response = await axios.get(`/api/status/${sessionId}`)
        setStatus(response.data)
        
        if (response.data.status === 'completed' && !report) {
          fetchReport()
        } else if (response.data.status === 'processing') {
          setTimeout(checkStatus, 1000) // Poll every 1 second for real-time updates
        }
      } catch (err) {
        setError(err.response?.data?.detail || 'Failed to fetch status')
      } finally {
        setLoading(false)
      }
    }

    const fetchReport = async () => {
      try {
        const response = await axios.get(`/api/report/${sessionId}`)
        setReport(response.data)
      } catch (err) {
        console.error('Failed to fetch report:', err)
      }
    }

    checkStatus()
  }, [sessionId, report])

  if (loading) {
    return (
      <div className="investigation-page">
        <div className="loading-state">
          <div className="spinner-large"></div>
          <h3>Loading investigation...</h3>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="investigation-page">
        <div className="error-state">
          <svg width="64" height="64" viewBox="0 0 64 64" fill="none">
            <circle cx="32" cy="32" r="30" stroke="#ef4444" strokeWidth="2"/>
            <path d="M32 20v16M32 44v.5" stroke="#ef4444" strokeWidth="3" strokeLinecap="round"/>
          </svg>
          <h3>Error Loading Investigation</h3>
          <p>{error}</p>
          <button className="btn btn-primary" onClick={onBackToUpload}>
            Upload New File
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="investigation-page">
      <div className="investigation-header">
        <div>
          <h2>Investigation Report</h2>
          <p className="session-id-text">Session: {sessionId}</p>
        </div>
        <div className="header-actions">
          <button className="btn btn-secondary" onClick={onBackToUpload}>
            <svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
              <path d="M10 18V6m0 12l-6-6m6 6l6-6" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" fill="none"/>
            </svg>
            New Upload
          </button>
          {report && (
            <button className="btn btn-primary" onClick={onOpenChatbot}>
              <svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
                <rect x="3" y="4" width="14" height="11" rx="2" stroke="currentColor" strokeWidth="2" fill="none"/>
                <path d="M7 9h6M7 12h4" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
              </svg>
              Open Chatbot
            </button>
          )}
        </div>
      </div>

      {status && (
        <div className="investigation-status card animate-fadeIn">
          <div className="status-header">
            <h3>Investigation Progress</h3>
            <span className={`badge ${
              status.status === 'completed' ? 'badge-success' :
              status.status === 'processing' ? 'badge-info' :
              status.status === 'failed' ? 'badge-error' : 'badge-warning'
            }`}>
              {status.status}
            </span>
          </div>
          
          <div className="progress-bar">
            <div 
              className="progress-bar-fill"
              style={{ width: `${status.progress || 0}%` }}
            ></div>
          </div>
          
          {status.current_message && status.status === 'processing' && (
            <ThinkingIndicator message={status.current_message} />
          )}
          
          <div className="progress-stages">
            {stages.map((stage, idx) => {
              const currentStageIdx = stages.findIndex(s => s.id === status.stage)
              const isActive = stage.id === status.stage
              const isCompleted = idx < currentStageIdx || status.status === 'completed'
              const isPending = idx > currentStageIdx && status.status !== 'completed'
              
              return (
                <div 
                  key={stage.id}
                  className={`progress-stage ${
                    isActive ? 'active' : 
                    isCompleted ? 'completed' : 
                    'pending'
                  }`}
                >
                  <div className={`stage-icon ${
                    isActive ? 'active' : 
                    isCompleted ? 'completed' : 
                    'pending'
                  }`}>
                    {isActive ? '⏳' : isCompleted ? '✓' : stage.icon}
                  </div>
                  <div className="stage-content">
                    <div className="stage-name">{stage.name}</div>
                    <div className={`stage-description ${isActive ? 'active' : ''}`}>
                      {isActive && status.current_message ? status.current_message : stage.description}
                    </div>
                  </div>
                  <div className="stage-status">
                    {isActive && <div className="spinner-small"></div>}
                    {isCompleted && <span className="checkmark">✓</span>}
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {report && (
        <>
          <div className="report-overview card animate-fadeIn">
            <h3>Executive Summary</h3>
            <div className="overview-grid">
              <div className="overview-item">
                <span className="overview-label">Report ID</span>
                <span className="overview-value">{report.metadata.report_id}</span>
              </div>
              <div className="overview-item">
                <span className="overview-label">Severity</span>
                <span className={`badge badge-${
                  report.metadata.severity === 'HIGH' ? 'error' :
                  report.metadata.severity === 'MEDIUM' ? 'warning' : 'info'
                }`}>
                  {report.metadata.severity}
                </span>
              </div>
              <div className="overview-item">
                <span className="overview-label">Timestamp</span>
                <span className="overview-value">
                  {new Date(report.metadata.timestamp).toLocaleString()}
                </span>
              </div>
              <div className="overview-item">
                <span className="overview-label">Signature Status</span>
                <span className="badge badge-success">
                  <svg width="14" height="14" viewBox="0 0 14 14" fill="currentColor" style={{marginRight: '0.25rem'}}>
                    <path d="M2 7l4 4 6-8" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" fill="none"/>
                  </svg>
                  Verified
                </span>
              </div>
            </div>
            {report.executive_summary && (
              <div className="summary-text">
                <p>{report.executive_summary}</p>
              </div>
            )}
          </div>

          {report.ioc_analysis && report.ioc_analysis.length > 0 && (
            <div className="ioc-section card animate-fadeIn">
              <h3>Indicators of Compromise (IOCs)</h3>
              <div className="ioc-stats">
                <div className="ioc-stat">
                  <span className="ioc-count">{report.ioc_analysis.length}</span>
                  <span className="ioc-label">Total IOCs</span>
                </div>
                <div className="ioc-stat">
                  <span className="ioc-count">
                    {report.ioc_analysis.filter(ioc => ioc.type === 'hash').length}
                  </span>
                  <span className="ioc-label">Hashes</span>
                </div>
                <div className="ioc-stat">
                  <span className="ioc-count">
                    {report.ioc_analysis.filter(ioc => ioc.type === 'ip').length}
                  </span>
                  <span className="ioc-label">IP Addresses</span>
                </div>
                <div className="ioc-stat">
                  <span className="ioc-count">
                    {report.ioc_analysis.filter(ioc => ioc.type === 'domain').length}
                  </span>
                  <span className="ioc-label">Domains</span>
                </div>
              </div>
              <div className="ioc-list">
                {report.ioc_analysis.map((ioc, idx) => (
                  <div key={idx} className="ioc-item">
                    <div className="ioc-header">
                      <span className={`badge badge-${
                        ioc.threat_level === 'high' ? 'error' :
                        ioc.threat_level === 'medium' ? 'warning' : 'info'
                      }`}>
                        {ioc.type}
                      </span>
                      <span className="ioc-value">{ioc.value}</span>
                    </div>
                    {ioc.threat_intel && (
                      <div className="ioc-details">
                        <p>{ioc.threat_intel}</p>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {report.attack_timeline && report.attack_timeline.length > 0 && (
            <div className="timeline-section card animate-fadeIn">
              <h3>Attack Timeline</h3>
              <div className="timeline">
                {report.attack_timeline.map((event, idx) => (
                  <div key={idx} className="timeline-item">
                    <div className="timeline-marker"></div>
                    <div className="timeline-content">
                      <div className="timeline-time">
                        {new Date(event.timestamp).toLocaleString()}
                      </div>
                      <div className="timeline-event">{event.event}</div>
                      {event.details && (
                        <div className="timeline-details">{event.details}</div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {report.recommendations && report.recommendations.length > 0 && (
            <div className="recommendations-section card animate-fadeIn">
              <h3>Recommendations</h3>
              <ul className="recommendations-list">
                {report.recommendations.map((rec, idx) => (
                  <li key={idx}>{rec}</li>
                ))}
              </ul>
            </div>
          )}
        </>
      )}
    </div>
  )
}

export default InvestigationPage
