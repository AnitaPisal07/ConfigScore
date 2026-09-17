import os
import sys
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner.core import run_security_scan
from database import init_db, get_recent_scans, get_scan_by_id

# Initialize database
init_db()

app = FastAPI(
    title="ConfigScore: Website Security Scanner API",
    description="Automated, non-intrusive website security configuration auditor and remediation solver.",
    version="1.0.0"
)

# Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    url: str

@app.post("/api/scan")
async def scan_website(req: ScanRequest):
    if not req.url or not req.url.strip():
        raise HTTPException(status_code=400, detail="Please provide a valid website URL.")
    try:
        results = await run_security_scan(req.url.strip())
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Audit failed: {str(e)}")

@app.get("/api/history")
async def get_history(limit: int = 15):
    return get_recent_scans(limit=limit)

@app.get("/api/scan/{scan_id}")
async def get_scan_details(scan_id: int):
    scan = get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found.")
    return scan

@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "ConfigScore Security Scanner",
        "version": "1.0.0"
    }

# Mount frontend static directory if exists
frontend_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend")
if os.path.exists(frontend_dir):
    app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

    @app.get("/")
    async def serve_frontend():
        index_file = os.path.join(frontend_dir, "index.html")
        if os.path.exists(index_file):
            return FileResponse(index_file)
        return {"message": "ConfigScore API is running. Access /docs for API documentation."}

if __name__ == "__main__":
    import uvicorn
    print("Starting ConfigScore Security Scanner on http://localhost:8000")
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
