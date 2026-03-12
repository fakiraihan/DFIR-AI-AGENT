import React from 'react'
import './ThinkingIndicator.css'

const ThinkingIndicator = ({ message }) => {
  return (
    <div className="thinking-indicator animate-fadeIn">
      <div className="thinking-dots">
        <div className="thinking-dot"></div>
        <div className="thinking-dot"></div>
        <div className="thinking-dot"></div>
      </div>
      <span className="thinking-message">{message}</span>
    </div>
  )
}

export default ThinkingIndicator
