import React from 'react'
import './Header.css'

const Header = ({ sidebarOpen, setSidebarOpen }) => {
  return (
    <header className="header">
      <div className="header-content">
        <button 
          className="sidebar-toggle"
          onClick={() => setSidebarOpen(!sidebarOpen)}
          aria-label="Toggle sidebar"
        >
          <svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
            <path d="M3 5h14M3 10h14M3 15h14" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
          </svg>
        </button>
        
        <div className="header-title">
          <svg className="logo-icon" width="32" height="32" viewBox="0 0 32 32" fill="none">
            <circle cx="16" cy="16" r="14" stroke="url(#gradient)" strokeWidth="2"/>
            <path d="M16 8v8l5.66 3.26" stroke="url(#gradient)" strokeWidth="2" strokeLinecap="round"/>
            <defs>
              <linearGradient id="gradient" x1="0" y1="0" x2="32" y2="32">
                <stop offset="0%" stopColor="#10b981"/>
                <stop offset="100%" stopColor="#059669"/>
              </linearGradient>
            </defs>
          </svg>
          <h1>AI Agent DFIR</h1>
          <span className="header-subtitle">Digital Forensics & Incident Response</span>
        </div>
        
        <div className="header-actions">
          <div className="status-indicator">
            <span className="status-dot"></span>
            <span>System Online</span>
          </div>
        </div>
      </div>
    </header>
  )
}

export default Header
