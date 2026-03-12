import React from 'react'
import './Sidebar.css'

const Sidebar = ({ isOpen, currentView, setCurrentView, sessionId }) => {
  const menuItems = [
    {
      id: 'upload',
      label: 'Upload Log',
      icon: (
        <svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
          <path d="M10 3v12m0-12l-4 4m4-4l4 4M3 17h14" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" fill="none"/>
        </svg>
      ),
      enabled: true
    },
    {
      id: 'investigation',
      label: 'Investigation',
      icon: (
        <svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
          <circle cx="9" cy="9" r="6" stroke="currentColor" strokeWidth="2" fill="none"/>
          <path d="M14 14l4 4" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
        </svg>
      ),
      enabled: !!sessionId
    },
    {
      id: 'chatbot',
      label: 'Chatbot',
      icon: (
        <svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
          <rect x="3" y="4" width="14" height="11" rx="2" stroke="currentColor" strokeWidth="2" fill="none"/>
          <path d="M7 9h6M7 12h4" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
        </svg>
      ),
      enabled: !!sessionId
    }
  ]

  return (
    <aside className={`sidebar ${isOpen ? 'open' : 'closed'}`}>
      <nav className="sidebar-nav">
        <div className="nav-section">
          <div className="nav-section-title">Navigation</div>
          {menuItems.map(item => (
            <button
              key={item.id}
              className={`nav-item ${currentView === item.id ? 'active' : ''} ${!item.enabled ? 'disabled' : ''}`}
              onClick={() => item.enabled && setCurrentView(item.id)}
              disabled={!item.enabled}
            >
              <span className="nav-icon">{item.icon}</span>
              <span className="nav-label">{item.label}</span>
            </button>
          ))}
        </div>

        {sessionId && (
          <div className="nav-section">
            <div className="nav-section-title">Session Info</div>
            <div className="session-info">
              <div className="session-id">
                <span className="session-label">Session ID</span>
                <span className="session-value">{sessionId.split('_')[1]}</span>
              </div>
            </div>
          </div>
        )}

        <div className="sidebar-footer">
          <div className="footer-info">
            <span className="footer-version">v1.0.0</span>
            <span className="footer-copyright">© 2026 Polsasbersan</span>
          </div>
        </div>
      </nav>
    </aside>
  )
}

export default Sidebar
