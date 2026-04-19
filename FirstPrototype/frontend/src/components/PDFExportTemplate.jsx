import React from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { Box, Typography } from '@mui/material';

const PDFExportTemplate = ({ content, metadata }) => {
  if (!content) return null;

  return (
    <Box
      sx={{
        width: '800px', // Standard A4 width-ish layout before scaling
        backgroundColor: '#ffffff',
        color: '#000000',
        padding: '40px',
        fontFamily: '"Times New Roman", Times, serif',
        lineHeight: 1.6,
        
        // Headings
        '& h1, & h2, & h3, & h4, & h5, & h6': {
          fontFamily: 'Arial, sans-serif',
          color: '#2b2b2b',
          fontWeight: 700,
          marginTop: '1.5em',
          marginBottom: '0.5em',
          lineHeight: 1.2,
        },
        '& h1': { fontSize: '24pt', borderBottom: '2px solid #eaeaea', paddingBottom: '4px', marginTop: 0 },
        '& h2': { fontSize: '18pt', borderBottom: '1px solid #eaeaea', paddingBottom: '4px' },
        '& h3': { fontSize: '14pt' },
        
        // Paragraphs
        '& p': {
          fontSize: '11pt',
          marginBottom: '1em',
          marginTop: 0,
        },
        
        // Lists
        '& ul, & ol': {
          fontSize: '11pt',
          paddingLeft: '2em',
          marginBottom: '1em',
        },
        '& li': {
          marginBottom: '0.25em',
        },
        
        // Tables
        '& table': {
          width: '100%',
          borderCollapse: 'collapse',
          marginBottom: '1.5em',
          fontSize: '10pt',
          fontFamily: 'Arial, sans-serif',
        },
        '& th, & td': {
          border: '1px solid #dddddd',
          padding: '8px 12px',
          textAlign: 'left',
        },
        '& th': {
          backgroundColor: '#f5f5f5',
          fontWeight: 700,
          color: '#333333',
        },
        '& tr:nth-of-type(even)': {
          backgroundColor: '#fafafa',
        },
        
        // Blockquotes
        '& blockquote': {
          margin: '0 0 1em 0',
          padding: '0.5em 1em',
          borderLeft: '4px solid #cccccc',
          backgroundColor: '#f9f9f9',
          fontStyle: 'italic',
        },
        
        // Code
        '& code': {
          fontFamily: '"Courier New", Courier, monospace',
          backgroundColor: '#f4f4f4',
          padding: '2px 4px',
          fontSize: '10pt',
          border: '1px solid #e0e0e0',
          borderRadius: '3px',
        },
        '& pre': {
          backgroundColor: '#f4f4f4',
          padding: '1em',
          overflowX: 'auto',
          border: '1px solid #e0e0e0',
          borderRadius: '4px',
        },
        '& pre code': {
          backgroundColor: 'transparent',
          border: 'none',
          padding: 0,
        }
      }}
    >
      <Box sx={{ mb: 4, pb: 2, borderBottom: '2px solid #2b2b2b' }}>
        <Typography variant="h4" sx={{ fontFamily: 'Arial, sans-serif', fontWeight: 'bold', mb: 1, color: '#2b2b2b' }}>
          Digital Forensics Incident Response Report
        </Typography>
        <Typography variant="body2" sx={{ fontFamily: 'Arial, sans-serif', color: '#555555' }}>
          Session ID: {metadata?.sessionId || 'Unknown'} | Generated: {new Date().toLocaleString()}
        </Typography>
      </Box>

      <ReactMarkdown remarkPlugins={[remarkGfm]}>
        {content}
      </ReactMarkdown>
    </Box>
  );
};

export default PDFExportTemplate;
