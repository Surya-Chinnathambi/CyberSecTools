from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import List, Optional
import os
from openai import OpenAI

from routers.auth import verify_token

router = APIRouter()

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
openai_client = OpenAI(api_key=OPENAI_API_KEY) if OPENAI_API_KEY else None

SECURITY_SYSTEM_PROMPT = """
You are an expert cybersecurity AI assistant specializing in:
- Network security analysis and threat assessment
- Vulnerability identification and remediation
- Penetration testing methodologies and best practices
- CVE analysis and risk evaluation
- Security compliance frameworks (OWASP, PCI-DSS, HIPAA)
- Incident response and forensics
- Security architecture and defense strategies

Provide detailed, actionable security advice. When discussing vulnerabilities:
1. Explain the technical details clearly
2. Assess the risk level and potential impact
3. Provide specific remediation steps
4. Reference relevant compliance frameworks
5. Suggest additional security measures

Always prioritize ethical security practices and responsible disclosure.
"""

class ChatMessage(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    message: str
    context: Optional[str] = None
    history: Optional[List[ChatMessage]] = []

class AnalyzeRequest(BaseModel):
    scan_type: str
    results: dict

@router.post("/message")
async def chat_message(
    request: ChatRequest,
    user_data: dict = Depends(verify_token)
):
    if not openai_client:
        raise HTTPException(status_code=503, detail="OpenAI API not configured")
    
    try:
        messages = [{"role": "system", "content": SECURITY_SYSTEM_PROMPT}]
        
        if request.context:
            messages.append({"role": "user", "content": f"Context: {request.context}"})
        
        for msg in request.history[-10:]:
            messages.append({"role": msg.role, "content": msg.content})
        
        messages.append({"role": "user", "content": request.message})
        
        response = openai_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=messages,
            max_tokens=2000
        )
        
        return {
            "message": response.choices[0].message.content,
            "role": "assistant"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Chat error: {str(e)}")

@router.post("/analyze")
async def analyze_scan(
    request: AnalyzeRequest,
    user_data: dict = Depends(verify_token)
):
    if not openai_client:
        raise HTTPException(status_code=503, detail="OpenAI API not configured")
    
    try:
        context_prompt = f"""
        Analyze these {request.scan_type} scan results and provide:
        1. Risk assessment and severity levels
        2. Detailed vulnerability explanations
        3. Specific remediation steps
        4. Compliance framework mapping
        5. Additional security recommendations
        
        Scan Results:
        {request.results}
        """
        
        messages = [
            {"role": "system", "content": SECURITY_SYSTEM_PROMPT},
            {"role": "user", "content": context_prompt}
        ]
        
        response = openai_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=messages,
            max_tokens=2000
        )
        
        return {
            "analysis": response.choices[0].message.content
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis error: {str(e)}")
