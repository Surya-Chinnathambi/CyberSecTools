from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
import os
import time

from routers import auth, scanning, chat, cve, shodan, exploits, billing, reports, dashboard
from utils.database import init_database

app = FastAPI(
    title="CyberSec AI Platform API",
    description="Comprehensive cybersecurity assessment platform with AI-powered analysis",
    version="2.0.0"
)

origins = [
    "http://localhost:3000",
    "http://localhost:5173",
    "https://*.replit.dev",
    "https://*.repl.co"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    return response

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": exc.errors(), "body": exc.body}
    )

@app.on_event("startup")
async def startup_event():
    init_database()

@app.get("/")
async def root():
    return {
        "name": "CyberSec AI Platform API",
        "version": "2.0.0",
        "status": "online"
    }

@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": time.time()}

app.include_router(auth.router, prefix="/api/auth", tags=["authentication"])
app.include_router(scanning.router, prefix="/api/scan", tags=["scanning"])
app.include_router(chat.router, prefix="/api/chat", tags=["ai-chat"])
app.include_router(cve.router, prefix="/api/cve", tags=["cve-database"])
app.include_router(shodan.router, prefix="/api/shodan", tags=["shodan"])
app.include_router(exploits.router, prefix="/api/exploits", tags=["exploits"])
app.include_router(billing.router, prefix="/api/billing", tags=["billing"])
app.include_router(reports.router, prefix="/api/reports", tags=["reports"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["dashboard"])

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 5000))
    uvicorn.run(app, host="0.0.0.0", port=port)
