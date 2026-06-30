import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    strictPort: true,
    proxy: {
      '/api': {
        target:       'http://localhost:8000',
        changeOrigin: true,
        rewrite:      path => path.replace(/^\/api/, ''),
        secure:       false,
      },
      '/ws-proxy': {
        target:       'ws://localhost:8000',
        ws:           true,
        changeOrigin: true,
        rewrite:      path => path.replace(/^\/ws-proxy/, '/ws'),
        secure:       false,
      },
    },
  },
})
