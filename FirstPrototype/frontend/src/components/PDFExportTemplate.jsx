import React from 'react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'

const PDF_REPORT_CSS = `
  .pdf-report {
    width: 100%;
    max-width: 100%;
    margin: 0;
    padding: 0;
    border: 0;
    box-shadow: none;
    background: #ffffff;
    color: #172033;
    font-family: "Segoe UI", Arial, sans-serif;
    line-height: 1.48;
    overflow: visible;
  }

  .pdf-report,
  .pdf-report * {
    box-sizing: border-box;
  }

  .pdf-report-cover {
    padding: 26px 42px;
    background: #0f172a;
    border-bottom: 4px solid #2563eb;
    color: #ffffff;
    break-inside: avoid;
    page-break-inside: avoid;
  }

  .pdf-report-kicker {
    font-size: 10pt;
    font-weight: 800;
    letter-spacing: 0;
    text-transform: none;
    opacity: 0.84;
  }

  .pdf-report-title {
    margin-top: 4px;
    font-size: 23pt;
    font-weight: 900;
    line-height: 1.12;
  }

  .pdf-report-meta {
    margin-top: 13px;
    display: grid;
    grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
    gap: 7px 22px;
    font-size: 8.5pt;
    opacity: 0.94;
  }

  .pdf-report-meta div {
    min-width: 0;
    overflow-wrap: anywhere;
  }

  .pdf-report-content {
    padding: 32px 42px;
    background: #ffffff;
  }

  .pdf-report-content > *:first-child {
    margin-top: 0;
  }

  .pdf-report-content h1 {
    display: none;
  }

  .pdf-report-content h2,
  .pdf-report-content h3,
  .pdf-report-content h4 {
    color: #0f172a;
    font-weight: 850;
    line-height: 1.22;
    break-after: avoid;
    page-break-after: avoid;
    break-inside: avoid;
    page-break-inside: avoid;
  }

  .pdf-report-content h2 {
    margin: 22px 0 10px 0;
    padding-bottom: 7px;
    border-bottom: 2px solid #2563eb;
    font-size: 15pt;
  }

  .pdf-report-content h3 {
    margin: 16px 0 7px 0;
    color: #164e63;
    font-size: 11.5pt;
  }

  .pdf-report-content p {
    margin: 0 0 9px 0;
    color: #263244;
    font-size: 9.4pt;
    orphans: 3;
    widows: 3;
  }

  .pdf-report-content ul,
  .pdf-report-content ol {
    margin: 0 0 11px 0;
    padding-left: 20px;
    color: #263244;
    font-size: 9.2pt;
  }

  .pdf-report-content li {
    margin-bottom: 4px;
    break-inside: avoid;
    page-break-inside: avoid;
  }

  .pdf-report-content li > p {
    margin-bottom: 0;
  }

  .pdf-report-content table {
    width: 100%;
    max-width: 100%;
    margin: 0 0 16px 0;
    border-collapse: separate;
    border-spacing: 0;
    table-layout: fixed;
    font-size: 8.1pt;
    break-inside: auto;
    page-break-inside: auto;
  }

  .pdf-report-content thead {
    display: table-header-group;
  }

  .pdf-report-content tr {
    break-inside: avoid;
    page-break-inside: avoid;
  }

  .pdf-report-content th,
  .pdf-report-content td {
    border: 0;
    border-top: 1px solid #d8e0ea;
    border-left: 1px solid #d8e0ea;
    padding: 6px 7px;
    text-align: left;
    vertical-align: top;
    overflow-wrap: anywhere;
    word-break: break-word;
  }

  .pdf-report-content tr > *:last-child {
    border-right: 1px solid #d8e0ea;
  }

  .pdf-report-content tbody tr:last-of-type > td {
    border-bottom: 1px solid #d8e0ea;
  }

  .pdf-report-content th {
    background: #e6f4f1;
    color: #0f172a;
    font-weight: 850;
  }

  .pdf-report-content tr:nth-of-type(even) td {
    background: #f8fafc;
  }

  .pdf-report-content code {
    padding: 1px 3px;
    border-radius: 3px;
    background: #eef2f7;
    color: #0f172a;
    font-family: "Cascadia Mono", Consolas, monospace;
    font-size: 8.3pt;
    overflow-wrap: anywhere;
  }

  .pdf-report-content pre {
    max-width: 100%;
    margin: 0 0 12px 0;
    padding: 9px 10px;
    border: 1px solid #d8e0ea;
    border-radius: 4px;
    background: #eef2f7;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    word-break: break-word;
    overflow-x: hidden;
  }

  .pdf-report-content pre code {
    display: block;
    padding: 0;
    border-radius: 0;
    background: transparent;
    white-space: pre-wrap;
  }

  .pdf-report-content img {
    max-width: 100%;
    height: auto;
  }

  .pdf-report-content blockquote {
    margin: 0 0 12px 0;
    padding: 8px 12px;
    border: 1px solid #bfdbfe;
    background: #eff6ff;
    color: #1e293b;
    break-inside: avoid;
    page-break-inside: avoid;
  }

  .pdf-report-content hr {
    height: 1px;
    margin: 16px 0;
    border: 0;
    background: #d8e0ea;
  }

  .pdf-report-footer {
    margin-top: 18px;
    padding: 13px 42px;
    border-top: 1px solid #d8e0ea;
    background: #f8fafc;
    color: #475569;
    display: flex;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 16px;
    font-size: 8pt;
  }

  .pdf-report-footer div {
    min-width: 0;
    overflow-wrap: anywhere;
  }
`

const PDFExportTemplate = ({ content, metadata }) => {
  if (!content) return null

  return (
    <div className="pdf-report">
      <style>{PDF_REPORT_CSS}</style>
      <div className="pdf-report-cover">
        <div className="pdf-report-kicker">Evidence-Bound DFIR Report</div>
        <div className="pdf-report-title">Detection and Analysis</div>
        <div className="pdf-report-meta">
          <div>Report ID: {metadata?.reportId || 'Unavailable'}</div>
          <div>Session ID: {metadata?.sessionId || 'Unavailable'}</div>
          <div>Severity: {metadata?.severity || 'Not assessed'}</div>
          <div>Generated: {new Date().toLocaleString()}</div>
        </div>
      </div>

      <div className="pdf-report-content">
        <ReactMarkdown remarkPlugins={[remarkGfm]} skipHtml>
          {content}
        </ReactMarkdown>
      </div>

      <div className="pdf-report-footer">
        <div>Source log: {metadata?.logFile || 'Unavailable'}</div>
        <div>Generated by JejakAgent</div>
      </div>
    </div>
  )
}

export default PDFExportTemplate
