# JejakAgent - Frontend

Frontend untuk JejakAgent, workspace DFIR dengan tema dark operasional yang fokus pada evidensi dan alur investigasi.

## 🎨 Fitur

- **Dark Theme** - Tampilan gelap modern untuk workspace investigasi siber
- **Upload Page** - Drag & drop untuk upload file log (.evtx, .log, .txt, .csv)
- **Investigation Page** - Progress tracking dan visualisasi hasil investigasi
- **Chatbot** - Interface chat untuk berinteraksi dengan AI Assistant
- **Responsive** - Tampilan responsive untuk berbagai ukuran layar
- **Real-time Status** - Update status investigasi secara real-time

## 📋 Prerequisites

1. **Node.js** (versi 18 atau lebih baru)
   - Download dari: https://nodejs.org/
   - Pilih versi LTS (Long Term Support)
   - Setelah install, restart terminal/PowerShell

2. **Backend API** sudah berjalan di http://localhost:8000

## 🚀 Cara Menjalankan

### 1. Install Dependencies

```bash
cd D:\FAKI\FirstPrototype\frontend
npm install
```

### 2. Jalankan Development Server

```bash
npm run dev
```

Frontend akan berjalan di: **http://localhost:3000**

### 3. Build untuk Production

```bash
npm run build
```

Hasil build akan ada di folder `dist/`

## 📁 Struktur File

```
frontend/
├── public/          # File statis
├── src/
│   ├── components/  # Komponen React
│   │   ├── Header.jsx
│   │   ├── Sidebar.jsx
│   │   ├── UploadPage.jsx
│   │   ├── InvestigationPage.jsx
│   │   └── ChatbotPage.jsx
│   ├── App.jsx      # Main component
│   ├── main.jsx     # Entry point
│   └── index.css    # Global styles
├── index.html
├── vite.config.js
└── package.json
```

## 🎯 Cara Menggunakan

### Upload Log File
1. Buka http://localhost:3000
2. Drag & drop file log atau klik untuk browse
3. Klik "Upload & Start Investigation"

### Melihat Hasil Investigation
1. Setelah upload, otomatis redirect ke Investigation Page
2. Lihat progress bar untuk tracking status
3. Setelah selesai, lihat:
   - Executive Summary
   - IOC Analysis (Indicators of Compromise)
   - Attack Timeline
   - Recommendations

### Chatbot
1. Dari Investigation Page, klik tombol "Open Chatbot"
2. Tanya apa saja tentang hasil investigasi
3. AI akan menjawab berdasarkan report yang dihasilkan

## 🔧 Troubleshooting

### npm not found
Install Node.js terlebih dahulu dari https://nodejs.org/

### Port 3000 sudah digunakan
Edit `vite.config.js` dan ubah port:
```js
server: {
  port: 3001, // ganti dengan port lain
  ...
}
```

### Backend tidak terkoneksi
Pastikan backend sudah berjalan di http://localhost:8000:
```bash
cd D:\FAKI\FirstPrototype\backend
python main.py
```

## 🎨 Customization

### Mengubah Warna Tema
Edit file CSS di `src/index.css` dan komponen CSS lainnya.
Primary color saat ini: `#2563eb` (calm blue)

### Mengubah Port Backend
Edit `vite.config.js`:
```js
proxy: {
  '/api': {
    target: 'http://localhost:8001', // ubah port backend
    changeOrigin: true
  }
}
```

## 📦 Tech Stack

- **React 18** - UI Library
- **Vite** - Build tool & dev server
- **Axios** - HTTP client
- **CSS3** - Styling (no framework, pure CSS)

## 🌐 API Endpoints yang Digunakan

- `POST /api/upload` - Upload file log
- `POST /api/investigate/{session_id}` - Start investigation
- `GET /api/status/{session_id}` - Get investigation status
- `GET /api/report/{session_id}` - Get investigation report
- `POST /api/chatbot/{session_id}` - Chat dengan AI assistant

## 📝 Notes

- Frontend menggunakan **pure CSS** tanpa framework seperti Tailwind/Bootstrap untuk kontrol penuh atas styling
- Semua komponen React dibuat dengan **functional components** dan hooks
- Design diarahkan sebagai **analyst workspace** yang evidence-first, kontras, dan operasional
- Animasi smooth untuk transisi antar page

## 👨‍💻 Developer

Faki Raihan - Polsasbersan TNI AL
Thesis Project 2026
