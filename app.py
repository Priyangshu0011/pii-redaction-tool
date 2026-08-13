import os
import shutil
import uuid
import markdown
import gc
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.requests import Request

from src.pii_detector import PIIDetector
from src.anonymizer import Anonymizer
from src.docx_processor import DocxProcessor
from src.evaluator import PIIEvaluator

app = FastAPI(
    title="PII Redaction & Anonymization Engine",
    description="Enterprise grade PII detection, redaction, and pseudonymization web application",
    version="1.0.0"
)

# Base directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMP_DIR = os.path.join(BASE_DIR, "temp_uploads")
STATIC_DIR = os.path.join(BASE_DIR, "static")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")

os.makedirs(TEMP_DIR, exist_ok=True)
os.makedirs(STATIC_DIR, exist_ok=True)
os.makedirs(TEMPLATES_DIR, exist_ok=True)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
templates = Jinja2Templates(directory=TEMPLATES_DIR)

detector = PIIDetector()
evaluator = PIIEvaluator(detector=detector)


@app.middleware("http")
async def add_no_cache_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    """Render the main interactive dashboard."""
    return templates.TemplateResponse(request=request, name="index.html")


@app.get("/evaluation-doc", response_class=HTMLResponse)
async def get_evaluation_doc(request: Request):
    """Render the Evaluation Strategy & Metrics document."""
    doc_path = os.path.join(BASE_DIR, "EVALUATION_STRATEGY_AND_METRICS.md")
    html_content = "<p>Documentation not found.</p>"
    if os.path.exists(doc_path):
        with open(doc_path, "r", encoding="utf-8") as f:
            md_text = f.read()
            html_content = markdown.markdown(md_text, extensions=['tables', 'fenced_code'])

    return templates.TemplateResponse(request=request, name="doc.html", context={"content": html_content})


@app.post("/api/redact")
async def redact_file(
    file: UploadFile = File(...),
    mode: str = Form("pseudonymize"),
    entity_types: str = Form("")
):
    """
    Process uploaded .docx file, redact PII, and return download link + stats.
    """
    if not file.filename.endswith(".docx"):
        raise HTTPException(status_code=400, detail="Only .docx files are supported.")

    file_id = str(uuid.uuid4())[:8]
    original_name = file.filename
    input_filename = f"{file_id}_{original_name}"
    output_filename = f"REDACTED_{file_id}_{original_name}"

    input_path = os.path.join(TEMP_DIR, input_filename)
    output_path = os.path.join(TEMP_DIR, output_filename)

    with open(input_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    try:
        selected_entities = [e.strip() for e in entity_types.split(",")] if entity_types else None
        anonymizer = Anonymizer(mode=mode)
        processor = DocxProcessor(detector=detector, anonymizer=anonymizer)

        stats = await run_in_threadpool(processor.process_document, input_path, output_path, selected_entities)
        gc.collect()

        return JSONResponse({
            "success": True,
            "filename": original_name,
            "download_url": f"/api/download/{output_filename}",
            "stats": stats
        })

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Redaction failed: {str(e)}")


@app.get("/api/download/{filename}")
async def download_file(filename: str):
    """Download processed redacted .docx file."""
    # Sanitize filename
    safe_filename = os.path.basename(filename)
    file_path = os.path.join(TEMP_DIR, safe_filename)

    # Check root workspace if file is the default assignment redacted docx
    if safe_filename == "Red_Herring_Prospectus_REDACTED.docx":
        file_path = os.path.join(BASE_DIR, safe_filename)

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Requested file not found.")

    return FileResponse(
        file_path,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        filename=safe_filename
    )


@app.get("/api/evaluation")
async def get_evaluation_metrics():
    """Return JSON evaluation metrics."""
    return evaluator.evaluate()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
