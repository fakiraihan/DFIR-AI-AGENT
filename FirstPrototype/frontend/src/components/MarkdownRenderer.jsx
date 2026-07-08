import React from 'react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { Box } from '@mui/material'

const MarkdownRenderer = ({ content }) => {
  if (!content) return null

  return (
    <Box
      sx={{
        color: 'text.primary',
        fontSize: '1rem',
        lineHeight: 1.8,
        fontFamily: '"Segoe UI Variable", Aptos, -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif',
        minWidth: 0,
        maxWidth: '100%',
        overflowWrap: 'anywhere',
        wordBreak: 'break-word',
        '& > *:first-of-type': { mt: 0 },
        '& > *:last-child': { mb: 0 },
        
        // Headings
        '& h1, & h2, & h3, & h4, & h5, & h6': {
          color: '#F8FAFC',
          fontWeight: 700,
          letterSpacing: 0,
          lineHeight: 1.3,
          mt: 4,
          mb: 2,
        },
        '& h1': { fontSize: '2.25rem', borderBottom: '1px solid', borderColor: 'divider', pb: 1 },
        '& h2': { fontSize: '1.75rem', borderBottom: '1px solid', borderColor: 'divider', pb: 1 },
        '& h3': { fontSize: '1.375rem' },
        '& h4': { fontSize: '1.125rem' },
        '& h5': { fontSize: '1rem' },
        '& h6': { fontSize: '0.875rem', color: 'text.secondary', textTransform: 'uppercase', letterSpacing: 0 },
        
        // Paragraphs
        '& p': {
          mt: 0,
          mb: 2,
          color: '#CBD5E1',
          minWidth: 0,
          overflowWrap: 'anywhere',
          wordBreak: 'break-word',
        },
        
        // Links
        '& a': {
          color: 'primary.main',
          textDecoration: 'none',
          borderBottom: '1px solid transparent',
          transition: 'border-color 0.2s ease',
          overflowWrap: 'anywhere',
          wordBreak: 'break-word',
          '&:hover': {
            borderColor: 'primary.main',
          }
        },
        
        // Lists
        '& ul, & ol': {
          mt: 0,
          mb: 2,
          pl: 3,
          color: '#CBD5E1',
          minWidth: 0,
        },
        '& li': {
          mb: 0.5,
          minWidth: 0,
          overflowWrap: 'anywhere',
          wordBreak: 'break-word',
        },
        '& li > p': {
          mb: 0,
        },
        
        // Emphasis
        '& strong': {
          fontWeight: 600,
          color: 'text.primary',
        },
        '& em': {
          fontStyle: 'italic',
        },
        
        // Blockquotes
        '& blockquote': {
          m: 0,
          mb: 3,
          px: 2.5,
          py: 1.5,
          border: '1px solid',
          borderColor: 'rgba(147, 197, 253, 0.22)',
          bgcolor: 'rgba(37, 99, 235, 0.08)',
          borderRadius: 2,
          color: '#F8FAFC',
          fontStyle: 'italic',
          '& p': {
            mb: 0,
            color: '#F8FAFC',
          }
        },
        
        // Inline Code
        '& code': {
          fontFamily: '"SFMono-Regular", Consolas, "Liberation Mono", Menlo, Courier, monospace',
          bgcolor: 'rgba(255, 255, 255, 0.08)',
          color: 'primary.light',
          px: 0.75,
          py: 0.25,
          borderRadius: 1,
          fontSize: '0.85em',
          overflowWrap: 'anywhere',
          wordBreak: 'break-word',
        },
        
        // Code Blocks
        '& pre': {
          mt: 0,
          mb: 3,
          p: 2.5,
          borderRadius: 2,
          maxWidth: '100%',
          overflowX: 'hidden',
          whiteSpace: 'pre-wrap',
          overflowWrap: 'anywhere',
          wordBreak: 'break-word',
          bgcolor: '#111827', // dark background for code blocks
          border: '1px solid',
          borderColor: 'divider',
          boxShadow: 'inset 0 1px 4px rgba(0,0,0,0.2)',
        },
        '& pre code': {
          bgcolor: 'transparent',
          color: '#e5e7eb', // light gray for text
          p: 0,
          borderRadius: 0,
          fontSize: '0.85em',
          lineHeight: 1.5,
          whiteSpace: 'pre-wrap',
          overflowWrap: 'anywhere',
          wordBreak: 'break-word',
        },
        
        // Tables
        '& table': {
          width: '100%',
          mb: 3,
          borderCollapse: 'collapse',
          fontSize: '0.95rem',
          display: 'block',
          maxWidth: '100%',
          overflowX: 'auto',
          whiteSpace: 'nowrap',
          bgcolor: 'rgba(255,255,255,0.02)',
          borderRadius: 8,
        },
        '& th, & td': {
          border: '1px solid rgba(255,255,255,0.1)',
          p: 2,
          textAlign: 'left',
        },
        '& th': {
          bgcolor: 'rgba(255,255,255,0.05)',
          fontWeight: 600,
          color: '#F8FAFC',
        },
        
        // Horizontal Rule
        '& hr': {
          my: 4,
          border: 0,
          height: '1px',
          bgcolor: 'divider',
        },
      }}
    >
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        skipHtml
        components={{
          a: ({ node, ...props }) => (
            <Box component="a" target="_blank" rel="noreferrer" {...props} />
          ),
        }}
      >
        {content}
      </ReactMarkdown>
    </Box>
  )
}

export default MarkdownRenderer
