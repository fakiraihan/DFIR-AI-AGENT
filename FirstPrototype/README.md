# AI Agent DFIR - Tool-Augmented LLM for Cybersecurity Incident Investigation

Sistem otomatisasi investigasi insiden siber menggunakan AI Agent berbasis LangGraph dengan Foundation-Sec-8B, DeepLog, dan Drain.

## 📋 Fitur Utama

- ✅ **Log Parsing**: Drain algorithm untuk ekstraksi template dari Windows EVTX, Sysmon, Linux logs
- ✅ **Anomaly Detection**: DeepLog (LSTM) terlatih pada 996k normal Windows logs
- ✅ **AI Agent**: LangGraph orchestration dengan Foundation-Sec-8B (local inference)
- ✅ **Threat Intelligence**: 6 API integrations (ThreatFox, MalwareBazaar, URLHaus, OTX, GreyNoise, VirusTotal)
- ⏳ **RAG Chatbot**: Query laporan investigasi (coming soon)
- ⏳ **React Frontend**: Web UI untuk upload dan visualisasi (coming soon)

## 📁 Struktur Proyek

```
FirstPrototype/
├── backend/
│   ├── main.py                    # FastAPI application
│   ├── config.py                  # Configuration management
│   ├── requirements.txt           # Python dependencies
│   ├── test_pipeline.py           # Full pipeline test
│   └── modules/
│       ├── parsing.py             # Drain log parser
│       ├── anomaly.py             # DeepLog anomaly detection
│       ├── agent.py               # LangGraph AI agent
│       ├── threat_intel.py        # Threat intel tool wrappers
│       └── report.py              # Report generation
├── data/                          # Uploaded logs (temporary)
├── output/                        # Investigation reports
└── models/                        # Model references
```

## 🚀 Quick Start

### 1. Prerequisites

- Python 3.10+
- Ollama dengan model Foundation-Sec-8B
- DeepLog model terlatih (dari LogADEmpirical-dev)
- CUDA-capable GPU (opsional, untuk performa lebih baik)

### 2. Setup Ollama & Foundation-Sec-8B

```bash
# Install Ollama (jika belum)
# Download dari: https://ollama.ai

# Buat model dari Modelfile
cd d:/FAKI/Sec-Foundation
ollama create foundation-sec-8b -f Modelfile

# Verifikasi model
ollama list
```

### 3. Install Dependencies

```bash
cd d:/FAKI/FirstPrototype/backend

# Create virtual environment
python -m venv venv

# Activate (Windows)
venv\Scripts\activate

# Install requirements
pip install -r requirements.txt
```

### 4. Configure Environment

```bash
# Copy .env.example to .env
copy .env.example .env

# Edit .env dan tambahkan API keys (opsional)
# notepad .env
```

### 5. Test Pipeline

```bash
# Run full pipeline test
python test_pipeline.py
```

Expected output:
- ✅ Parsing logs dengan Drain
- ✅ Deteksi anomali dengan DeepLog
- ✅ AI Agent investigation (jika Ollama running)
- ✅ Generate structured investigation report

### 6. Start API Server

```bash
# Run FastAPI server
python main.py

# atau dengan uvicorn
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

API akan tersedia di `http://localhost:8000`

## 🧪 Testing dengan Postman/curl

### 1. Upload Log File

```bash
curl -X POST "http://localhost:8000/api/upload" \
  -F "file=@path/to/logfile.evtx"
```

Response:
```json
{
  "session_id": "session_20260228_103045",
  "file_name": "logfile.evtx",
  "file_size": 12345,
  "message": "File uploaded successfully"
}
```

### 2. Start Investigation

```bash
curl -X POST "http://localhost:8000/api/investigate/session_20260228_103045"
```

Response:
```json
{
  "session_id": "session_20260228_103045",
  "status": "completed",
  "message": "Investigation completed successfully",
  "summary": {
    "parsed_logs": 4313,
    "templates": 156,
    "anomalies": 42,
    "severity": "HIGH",
    "report_id": "DFIR-20260228-103145"
  }
}
```

### 3. Get Investigation Status

```bash
curl "http://localhost:8000/api/status/session_20260228_103045"
```

### 4. Download Report

```bash
curl "http://localhost:8000/api/report/session_20260228_103045"
```

## 📊 Model & Dataset Info

### DeepLog Model
- **Location**: `d:/FAKI/LogADEmpirical-dev/output/Wintrim/sliding/W10_S5_CFalse_train0.8/models/DeepLog.pt`
- **Training Data**: 996,699 normal Windows CBS logs (Wintrim dataset)
- **Architecture**: LSTM (embedding=128, hidden=128, layers=2)
- **Detection Method**: Top-k prediction (k=9)
- **Performance**: 100% detection rate pada EVTX attack samples

### Test Dataset
- **Location**: `d:/FAKI/LogADEmpirical-dev/EVTX-ATTACK-SAMPLES/`
- **Total Files**: 200+ EVTX files
- **Categories**: 9 MITRE ATT&CK tactics
- **Total Events**: 4,313 attack events

## 🔧 Configuration

Edit `backend/.env`:

```bash
# Ollama
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=foundation-sec-8b

# Threat Intel API Keys (opsional)
THREATFOX_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
# ... dll

# DeepLog Parameters
DEEPLOG_WINDOW_SIZE=10
DEEPLOG_STEP_SIZE=5
DEEPLOG_TOPK=9
```

## 📖 API Documentation

Setelah server running, buka:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

## 🐛 Troubleshooting

### Ollama Connection Error
```
Error: Could not connect to Ollama
```
**Solution**:
1. Pastikan Ollama running: `ollama serve`
2. Cek model available: `ollama list`
3. Test model: `ollama run foundation-sec-8b "test"`

### DeepLog Model Not Found
```
Error: Model path not found
```
**Solution**:
1. Train DeepLog model terlebih dahulu di LogADEmpirical-dev
2. Atau update path di config.py

### Memory Error
```
RuntimeError: CUDA out of memory
```
**Solution**:
1. Reduce batch size di DeepLog config
2. Atau gunakan CPU inference (lebih lambat)

## 📚 References

### Papers
- **DeepLog**: Min Du et al. (CCS 2017) - "DeepLog: Anomaly Detection and Diagnosis from System Logs"
- **Drain**: Pinjia He et al. (ICWS 2017) - "Drain: An Online Log Parsing Approach"
- **LangGraph**: LangChain (2024) - Stateful agent orchestration framework

### Datasets
- **Wintrim**: Windows CBS logs (2014-2017, 996k entries)
- **EVTX-ATTACK-SAMPLES**: Public Windows attack logs (200+ files)
- **Loghub**: https://github.com/logpai/loghub

### Models
- **Foundation-Sec-8B**: Llama-3.1 based cybersecurity LLM
- **DeepLog**: LSTM-based log anomaly detector

## 👨‍💻 Development

### Running Tests
```bash
# Test individual modules
python modules/parsing.py
python modules/anomaly.py
python modules/agent.py
python modules/report.py

# Test full pipeline
python test_pipeline.py
```

### Adding New Threat Intel APIs
1. Add tool implementation in `modules/threat_intel.py`
2. Add tool to agent's tool selection in `modules/agent.py`
3. Update API key config in `.env.example`

## 📄 License

Sesuai dengan lisensi proyek tugas akhir Politeknik Siber dan Sandi Negara.

## 📧 Contact

Muhammad Faki Raihan - NPM 2221101820
Program Studi Rekayasa Kriptografi
Politeknik Siber dan Sandi Negara

---

**Status**: ✅ Backend Complete | ⏳ Frontend In Progress | ⏳ RAG Chatbot Planned
