from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import os
import tempfile
import shutil
from datetime import datetime
import hashlib
import mimetypes

from analyzers.pdf_analyzer import PDFAnalyzer
from analyzers.docx_analyzer import DOCXAnalyzer
from analyzers.image_analyzer import ImageAnalyzer
from analyzers.text_analyzer import TextAnalyzer
from analyzers.signature_analyzer import SignatureAnalyzer

app = FastAPI(title="Document Forgery Detection API", version="1.0.0")

# CORS middleware to allow frontend connections
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173", "http://localhost:8080"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {"message": "Document Forgery Detection API is running"}

@app.post("/api/analyze")
async def analyze_document(file: UploadFile = File(...)):
    """
    Analyze uploaded document for forgery detection
    """
    try:
        # Validate file
        if not file.filename:
            raise HTTPException(status_code=400, detail="No file provided")
        
        # Check file size (max 50MB)
        file_size = 0
        content = await file.read()
        file_size = len(content)
        
        if file_size > 50 * 1024 * 1024:  # 50MB
            raise HTTPException(status_code=400, detail="File too large (max 50MB)")
        
        # Reset file pointer
        await file.seek(0)
        
        # Create temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{file.filename}") as temp_file:
            shutil.copyfileobj(file.file, temp_file)
            temp_file_path = temp_file.name
        
        try:
            # Get file info
            file_info = {
                "filename": file.filename,
                "size": file_size,
                "type": file.content_type or mimetypes.guess_type(file.filename)[0],
                "upload_time": datetime.now().isoformat()
            }
            
            # Initialize analyzers
            pdf_analyzer = PDFAnalyzer()
            docx_analyzer = DOCXAnalyzer()
            image_analyzer = ImageAnalyzer()
            text_analyzer = TextAnalyzer()
            signature_analyzer = SignatureAnalyzer()
            
            # Extract metadata based on file type
            metadata = await extract_metadata(temp_file_path, file_info, pdf_analyzer, docx_analyzer)
            
            # Perform text analysis
            text_analysis = await text_analyzer.analyze(temp_file_path, file_info)
            
            # Perform image analysis
            image_analysis = await image_analyzer.analyze(temp_file_path, file_info)
            
            # Perform signature analysis
            signature_check = await signature_analyzer.analyze(temp_file_path, file_info)
            
            return JSONResponse({
                "success": True,
                "metadata": metadata,
                "textAnalysis": text_analysis,
                "imageAnalysis": image_analysis,
                "signatureCheck": signature_check,
                "analysisTime": datetime.now().isoformat()
            })
            
        finally:
            # Clean up temporary file
            if os.path.exists(temp_file_path):
                os.unlink(temp_file_path)
                
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

async def extract_metadata(file_path: str, file_info: dict, pdf_analyzer, docx_analyzer):
    """Extract real metadata from the file"""
    base_metadata = {
        "filename": file_info["filename"],
        "size": file_info["size"],
        "type": file_info["type"],
        "lastModified": file_info["upload_time"],
    }
    
    file_type = file_info["type"]
    
    if file_type == "application/pdf":
        pdf_metadata = await pdf_analyzer.extract_metadata(file_path)
        return {**base_metadata, **pdf_metadata}
    elif file_type in ["application/vnd.openxmlformats-officedocument.wordprocessingml.document", "application/msword"]:
        docx_metadata = await docx_analyzer.extract_metadata(file_path)
        return {**base_metadata, **docx_metadata}
    else:
        return {
            **base_metadata,
            "author": "Not available for this file type",
            "createdDate": None,
            "modifiedDate": None
        }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
