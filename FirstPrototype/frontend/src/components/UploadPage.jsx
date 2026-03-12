import React, { useState, useRef } from 'react'
import './UploadPage.css'
import axios from 'axios'

const UploadPage = ({ onUploadSuccess }) => {
  const [file, setFile] = useState(null)
  const [uploading, setUploading] = useState(false)
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

  const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 Bytes'
    const k = 1024
    const sizes = ['Bytes', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i]
  }

  return (
    <div className="upload-page">
      <div className="upload-container animate-fadeIn">
        <div className="upload-header">
          <h2>Upload Log File</h2>
          <p>Start your forensic investigation by uploading a log file</p>
        </div>

        <div 
          className={`upload-dropzone ${dragActive ? 'drag-active' : ''} ${file ? 'has-file' : ''}`}
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
            <div className="dropzone-content">
              <svg className="upload-icon" width="64" height="64" viewBox="0 0 64 64" fill="none">
                <circle cx="32" cy="32" r="30" stroke="url(#gradient)" strokeWidth="2" strokeDasharray="4 4"/>
                <path d="M32 20v24m0-24l-8 8m8-8l8 8" stroke="url(#gradient)" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"/>
                <defs>
                  <linearGradient id="gradient" x1="0" y1="0" x2="64" y2="64">
                    <stop offset="0%" stopColor="#10b981"/>
                    <stop offset="100%" stopColor="#059669"/>
                  </linearGradient>
                </defs>
              </svg>
              <h3>Drop your log file here</h3>
              <p>or click to browse</p>
              <div className="file-types">
                <span className="file-badge">.evtx</span>
                <span className="file-badge">.log</span>
                <span className="file-badge">.txt</span>
                <span className="file-badge">.csv</span>
              </div>
            </div>
          ) : (
            <div className="file-preview">
              <svg className="file-icon" width="48" height="48" viewBox="0 0 48 48" fill="none">
                <rect x="10" y="6" width="28" height="36" rx="2" stroke="#10b981" strokeWidth="2"/>
                <path d="M16 16h16M16 24h16M16 32h12" stroke="#10b981" strokeWidth="2" strokeLinecap="round"/>
              </svg>
              <div className="file-info">
                <div className="file-name">{file.name}</div>
                <div className="file-size">{formatFileSize(file.size)}</div>
              </div>
              <button 
                className="btn-remove"
                onClick={(e) => {
                  e.stopPropagation()
                  setFile(null)
                }}
              >
                <svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
                  <path d="M6 6l8 8M14 6l-8 8" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
                </svg>
              </button>
            </div>
          )}
        </div>

        {error && (
          <div className="error-message animate-fadeIn">
            <svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
              <circle cx="10" cy="10" r="9" stroke="currentColor" strokeWidth="2" fill="none"/>
              <path d="M10 6v5M10 14v.5" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
            </svg>
            {error}
          </div>
        )}

        <div className="upload-actions">
          <button 
            className="btn btn-primary"
            onClick={handleUpload}
            disabled={!file || uploading}
          >
            {uploading ? (
              <>
                <div className="spinner"></div>
                Starting Investigation...
              </>
            ) : (
              <>
                <svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
                  <path d="M10 3v12m0-12l-4 4m4-4l4 4M3 17h14" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" fill="none"/>
                </svg>
                Start Investigation
              </>
            )}
          </button>
        </div>

        <div className="upload-info">
          <div className="info-card">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
              <circle cx="12" cy="12" r="10" stroke="#10b981" strokeWidth="2"/>
              <path d="M12 8v4M12 16v.5" stroke="#10b981" strokeWidth="2" strokeLinecap="round"/>
            </svg>
            <div>
              <h4>What happens next?</h4>
              <ul>
                <li>Log parsing with Drain algorithm</li>
                <li>Anomaly detection using DeepLog</li>
                <li>AI Agent investigation with threat intelligence</li>
                <li>Signed investigation report generation</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default UploadPage
