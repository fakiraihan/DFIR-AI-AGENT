import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  optimizeDeps: {
    include: ['docx']
  },
  server: {
    host: true, // Expose to local network (0.0.0.0)
    allowedHosts: true, // Allow tunneling hosts like localtunnel
    port: 3000,
    proxy: {
      '/api': {
        target: process.env.VITE_API_PROXY_TARGET || 'http://localhost:8000',
        changeOrigin: true
      }
    }
  }
})
