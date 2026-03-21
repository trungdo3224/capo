from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from typing import List, Dict, Any
from pathlib import Path

from capo.config import CORS_ALLOWED_ORIGINS
from capo.studio.schemas import CheatsheetModel, MethodologyModel
from capo.studio.yaml_manager import YamlManager

# Get paths relative to this file
PACKAGE_DIR = Path(__file__).parent.parent
CHEATSHEET_DIR = PACKAGE_DIR / "core_cheatsheets"
METHODOLOGY_DIR = PACKAGE_DIR / "core_methodologies"
FRONTEND_DIR = PACKAGE_DIR.parent / "frontend"

app = FastAPI(title="Capo Studio API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ALLOWED_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)

yaml_mgr = YamlManager(str(CHEATSHEET_DIR), str(METHODOLOGY_DIR))

# API Routes
@app.get("/api/cheatsheets")
def list_cheatsheets() -> List[str]:
    return yaml_mgr.list_cheatsheets()

@app.get("/api/cheatsheets/{filename}")
def get_cheatsheet(filename: str) -> Dict[str, Any]:
    try:
        return yaml_mgr.get_cheatsheet(filename)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Cheatsheet not found")

@app.post("/api/cheatsheets/{filename}")
def save_cheatsheet(filename: str, data: Dict[str, Any]):
    try:
        CheatsheetModel(**data)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    yaml_mgr.save_cheatsheet(filename, data)
    return {"status": "success", "file": filename}


@app.get("/api/methodologies")
def list_methodologies() -> List[str]:
    return yaml_mgr.list_methodologies()

@app.get("/api/methodologies/{filename}")
def get_methodology(filename: str) -> Dict[str, Any]:
    try:
        return yaml_mgr.get_methodology(filename)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Methodology not found")

@app.post("/api/methodologies/{filename}")
def save_methodology(filename: str, data: Dict[str, Any]):
    try:
        MethodologyModel(**data)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    yaml_mgr.save_methodology(filename, data)
    return {"status": "success", "file": filename}

# Serve the static frontend
# Mount the root / to serve index.html directly
@app.get("/")
def serve_index():
    return FileResponse(FRONTEND_DIR / "index.html")

app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
