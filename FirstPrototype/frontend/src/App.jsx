import React, { useState } from 'react'
import './App.css'
import Header from './components/Header'
import Sidebar from './components/Sidebar'
import UploadPage from './components/UploadPage'
import InvestigationPage from './components/InvestigationPage'
import ChatbotPage from './components/ChatbotPage'

function App() {
  const [currentView, setCurrentView] = useState('upload') // upload, investigation, chatbot
  const [sessionId, setSessionId] = useState(null)
  const [sidebarOpen, setSidebarOpen] = useState(true)

  const handleUploadSuccess = (newSessionId) => {
    setSessionId(newSessionId)
    setCurrentView('investigation')
  }

  const handleBackToUpload = () => {
    setCurrentView('upload')
    setSessionId(null)
  }

  const handleOpenChatbot = () => {
    setCurrentView('chatbot')
  }

  return (
    <div className="app">
      <Header 
        sidebarOpen={sidebarOpen}
        setSidebarOpen={setSidebarOpen}
      />
      
      <div className="app-container">
        <Sidebar 
          isOpen={sidebarOpen}
          currentView={currentView}
          setCurrentView={setCurrentView}
          sessionId={sessionId}
        />
        
        <main className={`main-content ${sidebarOpen ? '' : 'full-width'}`}>
          {currentView === 'upload' && (
            <UploadPage onUploadSuccess={handleUploadSuccess} />
          )}
          
          {currentView === 'investigation' && sessionId && (
            <InvestigationPage 
              sessionId={sessionId}
              onBackToUpload={handleBackToUpload}
              onOpenChatbot={handleOpenChatbot}
            />
          )}
          
          {currentView === 'chatbot' && sessionId && (
            <ChatbotPage 
              sessionId={sessionId}
              onBack={() => setCurrentView('investigation')}
            />
          )}
        </main>
      </div>
    </div>
  )
}

export default App
