import React from 'react'
import { Box, Typography, CircularProgress } from '@mui/material'

const ThinkingIndicator = ({ stageLabel, message }) => {
  return (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, p: 2, bgcolor: 'rgba(255,255,255,0.02)', borderRadius: 2.5, border: '1px solid', borderColor: 'divider', my: 2 }}>
      <CircularProgress size={20} color="primary" />
      <Box>
        {stageLabel && (
          <Typography variant="caption" color="primary.main" sx={{ fontWeight: 700, display: 'block', mb: 0.25 }}>
            {stageLabel}
          </Typography>
        )}
        <Typography variant="body2" color="text.secondary">
          {message}
        </Typography>
      </Box>
    </Box>
  )
}

export default ThinkingIndicator
