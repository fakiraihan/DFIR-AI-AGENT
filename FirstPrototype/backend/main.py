"""
AI Agent DFIR - Main FastAPI Application
Orchestrates log parsing, anomaly detection, AI agent investigation, and report generation
"""

from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn
import os
from pathlib import Path
from typing import Optional
import json
from datetime import datetime
import sys

app = FastAPI(
    title="AI Agent DFIR",
    description="Tool-Augmented LLM untuk Otomatisasi Investigasi Insiden Siber",
    version="1.0.0"
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # React default port
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global paths
BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data" / "raw_logs"
OUTPUT_DIR = BASE_DIR / "output"
MODELS_DIR = BASE_DIR / "models"

# Create directories if they don't exist
DATA_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Store active investigation sessions
active_sessions = {}

def update_session_status(session_id: str, stage: str, message: str, progress: int):
    """Update session status with detailed progress"""
    if session_id in active_sessions:
        active_sessions[session_id].update({
            "stage": stage,
            "current_message": message,
            "progress": progress,
            "last_update": datetime.now().isoformat()
        })
        # Force print to console with flush for real-time visibility
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"\n[{timestamp}] [{session_id}] {stage.upper()}: {message}", flush=True)
        sys.stdout.flush()


def run_investigation_pipeline(session_id: str):
    """
    Background task: Run full investigation pipeline
    """
    try:
        session = active_sessions[session_id]
        file_path = session["file_path"]
        
        print(f"\n{'='*80}")
        print(f"STARTING INVESTIGATION: {session_id}")
        print(f"File: {session['file_name']}")
        print(f"{'='*80}\n")
        
        # Import modules
        from modules.parsing import parse_log_file
        from modules.anomaly import detect_anomalies_in_logs
        from modules.agent import DFIRAgent
        from modules.report import ReportGenerator
        from config import settings
        
        # Stage 1: Parsing
        update_session_status(session_id, "parsing", "Memuat file log...", 10)
        print(f"\n{'='*80}")
        print("STAGE 1: LOG PARSING")
        print(f"{'='*80}")
        
        update_session_status(session_id, "parsing", "Sedang melakukan parsing logs dengan Drain algorithm...", 15)
        parsed_df, templates = parse_log_file(
            file_path,
            depth=settings.drain_depth,
            sim_threshold=settings.drain_sim_threshold,
            max_children=settings.drain_max_children
        )
        session["parsed_logs_count"] = len(parsed_df)
        session["templates_count"] = len(templates)
        print(f"✓ Parsing complete: {len(parsed_df)} events, {len(templates)} templates")
        update_session_status(session_id, "parsing", f"✓ Parsing selesai: {len(parsed_df)} events, {len(templates)} templates", 25)
        
        # Stage 2: Anomaly Detection
        update_session_status(session_id, "anomaly_detection", "Memuat model DeepLog...", 30)
        print(f"\n{'='*80}")
        print("STAGE 2: ANOMALY DETECTION")
        print(f"{'='*80}")
        
        # Get model paths from LogADEmpirical
        logad_path = BASE_DIR.parent / "LogADEmpirical-dev"
        model_path = logad_path / "output" / "Wintrim" / "sliding" / "W10_S5_CFalse_train0.8" / "models" / "DeepLog.pt"
        vocab_path = logad_path / "output" / "Wintrim" / "sliding" / "W10_S5_CFalse_train0.8" / "vocabs" / "DeepLog.pkl"
        
        print(f"Loading DeepLog model from: {model_path}")
        update_session_status(session_id, "anomaly_detection", "Sedang melakukan deteksi anomali dengan DeepLog...", 40)
        results_df, anomalies_df = detect_anomalies_in_logs(
            parsed_df,
            str(model_path),
            str(vocab_path),
            window_size=settings.deeplog_window_size,
            step_size=settings.deeplog_step_size,
            topk=settings.deeplog_topk
        )
        session["anomalies_count"] = len(anomalies_df)
        print(f"✓ DeepLog complete: {len(anomalies_df)} anomalies detected")
        update_session_status(session_id, "anomaly_detection", f"✓ DeepLog selesai: {len(anomalies_df)} anomalies detected", 45)
        
        # Stage 2.5: LLM Filtering (Second Gate)
        update_session_status(session_id, "anomaly_detection", "🤖 LLM sedang memfilter anomalies (second gate)...", 47)
        print(f"\n{'='*80}")
        print("STAGE 2.5: LLM ANOMALY FILTERING")
        print(f"{'='*80}")
        
        from modules.llm_filter import LLMAnomalyFilter
        llm_filter = LLMAnomalyFilter(
            ollama_base_url=settings.ollama_base_url,
            ollama_model=settings.ollama_model
        )
        
        print(f"Filtering {len(anomalies_df)} anomalies with LLM...")
        # Filter anomalies with LLM
        filtered_anomalies_df = llm_filter.filter_anomalies(anomalies_df, parsed_df)
        session["deeplog_anomalies"] = len(anomalies_df)
        session["llm_filtered_anomalies"] = len(filtered_anomalies_df)
        session["anomalies_count"] = len(filtered_anomalies_df)
        
        print(f"✓ LLM Filter: {len(anomalies_df)} → {len(filtered_anomalies_df)} confirmed anomalies")
        update_session_status(
            session_id, 
            "anomaly_detection", 
            f"✓ LLM Filter: {len(anomalies_df)} → {len(filtered_anomalies_df)} confirmed anomalies", 
            50
        )
        
        # Use filtered anomalies for investigation
        anomalies_df = filtered_anomalies_df
        
        # Stage 3: AI Agent Investigation
        update_session_status(session_id, "ai_agent", "Menginisialisasi AI Agent...", 55)
        print(f"\n{'='*80}")
        print("STAGE 3: AI AGENT INVESTIGATION")
        print(f"{'='*80}")
        
        agent = DFIRAgent(
            ollama_base_url=settings.ollama_base_url,
            ollama_model=settings.ollama_model,
            threat_intel_api_keys={
                "abusech_api_key": settings.abusech_api_key,
                "alienvault_otx_api_key": settings.alienvault_otx_api_key,
                "greynoise_api_key": settings.greynoise_api_key,
                "virustotal_api_key": settings.virustotal_api_key
            }
        )
        
        print("Agent initialized, starting investigation...")
        update_session_status(session_id, "ai_agent", "🤖 AI sedang mengekstrak IOCs...", 60)
        # Pass session_id to agent for status updates
        investigation_state = agent.investigate(anomalies_df, parsed_df, session_id, update_session_status)
        
        # Stage 4: Report Generation
        update_session_status(session_id, "report_generation", "Menyusun laporan investigasi...", 85)
        print(f"\n{'='*80}")
        print("STAGE 4: REPORT GENERATION")
        print(f"{'='*80}")
        
        report_generator = ReportGenerator(
            private_key_path=str(BASE_DIR.parent / "keys" / "private.pem"),
            public_key_path=str(BASE_DIR.parent / "keys" / "public.pem")
        )
        
        # Generate keys if they don't exist
        if not report_generator.private_key:
            print("Generating RSA-2048 keypair...")
            report_generator.generate_keypair(str(BASE_DIR.parent / "keys"))
        
        print("Generating report...")
        report = report_generator.generate_report(
            session_id,
            session["file_name"],
            investigation_state
        )
        
        update_session_status(session_id, "report_generation", "Menandatangani laporan dengan RSA-2048...", 90)
        print("Signing report with RSA-2048...")
        signature = report_generator.sign_report(report)
        
        # Save report
        print("Saving report (PDF and JSON)...")
        report_path = report_generator.save_report(
            report,
            signature,
            str(OUTPUT_DIR / session_id)
        )
        
        # Update session
        update_session_status(session_id, "completed", "✓ Investigasi selesai! Laporan telah ditandatangani.", 100)
        session["status"] = "completed"
        session["stage"] = "completed"
        session["report"] = report
        session["signature"] = signature
        session["report_path"] = report_path
        session["completion_time"] = datetime.now().isoformat()
        
        print(f"\n{'='*80}")
        print(f"INVESTIGATION COMPLETED: {session_id}")
        print(f"Report saved to: {report_path}")
        print(f"{'='*80}\n")
        
    except Exception as e:
        import traceback
        session = active_sessions.get(session_id, {})
        session["status"] = "error"
        session["error"] = str(e)
        session["traceback"] = traceback.format_exc()
        print(f"\n{'='*80}")
        print(f"ERROR IN INVESTIGATION: {session_id}")
        print(f"{'='*80}")
        print(f"Error: {e}")
        print(traceback.format_exc())
        print(f"{'='*80}\n")


@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "status": "online",
        "service": "AI Agent DFIR",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat()
    }


@app.post("/api/upload")
async def upload_log_file(file: UploadFile = File(...)):
    """
    Upload log file for investigation
    Supports: .evtx, .log, .txt, .csv
    """
    try:
        # Validate file extension
        allowed_extensions = ['.evtx', '.log', '.txt', '.csv']
        file_ext = os.path.splitext(file.filename)[1].lower()
        
        if file_ext not in allowed_extensions:
            raise HTTPException(
                status_code=400,
                detail=f"File type not supported. Allowed: {', '.join(allowed_extensions)}"
            )
        
        # Generate session ID
        session_id = f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        session_dir = DATA_DIR / session_id
        session_dir.mkdir(parents=True, exist_ok=True)
        
        # Save uploaded file
        file_path = session_dir / file.filename
        content = await file.read()
        with open(file_path, 'wb') as f:
            f.write(content)
        
        # Initialize session
        active_sessions[session_id] = {
            "file_name": file.filename,
            "file_path": str(file_path),
            "file_size": len(content),
            "upload_time": datetime.now().isoformat(),
            "status": "uploaded",
            "stage": "pending"
        }
        
        return {
            "session_id": session_id,
            "file_name": file.filename,
            "file_size": len(content),
            "message": "File uploaded successfully"
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/investigate/{session_id}")
async def start_investigation(session_id: str, background_tasks: BackgroundTasks):
    """
    Start full investigation pipeline in background:
    1. Drain parsing
    2. DeepLog anomaly detection
    3. LLM anomaly filtering
    4. AI Agent orchestration with threat intel
    5. Report generation with digital signature
    """
    if session_id not in active_sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    
    try:
        session = active_sessions[session_id]
        session["status"] = "processing"
        session["stage"] = "pending"
        session["progress"] = 0
        session["current_message"] = "Investigation akan segera dimulai..."
        
        # Run investigation in background
        background_tasks.add_task(run_investigation_pipeline, session_id)
        
        return {
            "session_id": session_id,
            "status": "processing",
            "message": "Investigation started in background. Check /api/status/{session_id} for progress."
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/status/{session_id}")
async def get_investigation_status(session_id: str):
    """Get current status of investigation"""
    if session_id not in active_sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    
    return active_sessions[session_id]


@app.get("/api/report/{session_id}")
async def get_report(session_id: str):
    """Retrieve final investigation report"""
    if session_id not in active_sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    
    session = active_sessions[session_id]
    
    if session.get("status") != "completed":
        raise HTTPException(
            status_code=400,
            detail="Investigation not completed yet"
        )
    
    # TODO: Load and return actual report
    return {
        "session_id": session_id,
        "report": session.get("report", {}),
        "signature": session.get("signature", {}),
        "timestamp": session.get("completion_time")
    }


@app.post("/api/chatbot/{session_id}")
async def chatbot_query(session_id: str, query: dict):
    """
    RAG-based chatbot for querying the investigation report
    Read-only mode - no tool calls allowed
    """
    if session_id not in active_sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    
    session = active_sessions[session_id]
    
    if session.get("status") != "completed":
        raise HTTPException(
            status_code=400,
            detail="Investigation must be completed before chatbot access"
        )
    
    user_query = query.get("query", "")
    
    # TODO: Implement RAG pipeline
    # from modules.chatbot import rag_query
    
    return {
        "session_id": session_id,
        "query": user_query,
        "response": "Chatbot RAG implementation pending",
        "timestamp": datetime.now().isoformat()
    }


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )
