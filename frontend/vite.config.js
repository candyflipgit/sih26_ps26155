import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    // The API is proxied so the browser makes same-origin requests and the
    // deployed build needs no environment-specific base URL.
    proxy: { '/api': { target: 'http://127.0.0.1:8077', changeOrigin: true } },
  },
})
