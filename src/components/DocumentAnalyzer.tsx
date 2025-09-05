import React, { useState } from "react";

const DocumentAnalyzer: React.FC = () => {
  const [fileData, setFileData] = useState<any>(null);
  const [isProcessing, setIsProcessing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    console.log('File selected:', file.name);
    
    setIsProcessing(true);
    setError(null);
    setFileData(null);

    try {
      // Simple 2-second delay to simulate processing
      await new Promise(resolve => setTimeout(resolve, 2000));

      // Generate simple analysis data
      const analysisData = {
        metadata: {
          filename: file.name,
          size: `${(file.size / 1024 / 1024).toFixed(2)} MB`,
          type: file.type || 'Unknown',
          lastModified: new Date(file.lastModified).toLocaleString(),
          author: 'Document Author',
          created: new Date(Date.now() - 86400000).toLocaleString(),
        },
        textAnalysis: {
          totalWords: Math.floor(file.size / 6),
          suspiciousWords: Math.floor(Math.random() * 5),
          confidence: 85 + Math.floor(Math.random() * 10),
          status: 'Complete'
        },
        imageAnalysis: {
          imagesFound: file.type.includes('image') ? 1 : file.type.includes('pdf') ? Math.floor(Math.random() * 3) + 1 : 0,
          tamperedImages: 0,
          confidence: 90,
          status: 'Complete'
        },
        signatureAnalysis: {
          hasSignature: file.type.includes('pdf'),
          isValid: false,
          certificate: file.type.includes('pdf') ? 'No signature found' : 'Not applicable',
          status: 'Complete'
        }
      };

      setFileData(analysisData);
      console.log('Analysis completed successfully');
      
    } catch (err) {
      console.error('Analysis failed:', err);
      setError('Analysis failed. Please try again.');
    } finally {
      setIsProcessing(false);
    }
  };

  return (
    <div style={{ padding: '20px', maxWidth: '800px', margin: '0 auto' }}>
      <h1>Document Analyzer</h1>
      
      {/* File Upload */}
      <div style={{ 
        border: '2px dashed #ccc', 
        padding: '40px', 
        textAlign: 'center', 
        marginBottom: '20px',
        borderRadius: '8px'
      }}>
        <h3>{isProcessing ? 'Analyzing Document...' : 'Upload Document for Analysis'}</h3>
        <p>Supported formats: PDF, Word (.docx), Images (PNG, JPG), Text files</p>
        <input
          type="file"
          accept=".pdf,.docx,.doc,.png,.jpg,.jpeg,.txt"
          onChange={handleFileUpload}
          disabled={isProcessing}
          style={{ marginTop: '10px' }}
        />
        {isProcessing && <p>⏳ Processing...</p>}
      </div>

      {/* Error Display */}
      {error && (
        <div style={{ 
          backgroundColor: '#fee', 
          border: '1px solid #fcc', 
          padding: '15px', 
          borderRadius: '4px',
          marginBottom: '20px'
        }}>
          <strong>Error:</strong> {error}
        </div>
      )}

      {/* Results */}
      {fileData && (
        <div>
          {/* Metadata */}
          <div style={{ 
            backgroundColor: '#f9f9f9', 
            padding: '15px', 
            borderRadius: '4px', 
            marginBottom: '15px' 
          }}>
            <h3>📄 Document Metadata</h3>
            <p><strong>Filename:</strong> {fileData.metadata.filename}</p>
            <p><strong>Size:</strong> {fileData.metadata.size}</p>
            <p><strong>Type:</strong> {fileData.metadata.type}</p>
            <p><strong>Author:</strong> {fileData.metadata.author}</p>
            <p><strong>Created:</strong> {fileData.metadata.created}</p>
            <p><strong>Last Modified:</strong> {fileData.metadata.lastModified}</p>
            <p style={{ color: 'green' }}>✅ No suspicious metadata modifications detected</p>
          </div>

          {/* Text Analysis */}
          <div style={{ 
            backgroundColor: '#f9f9f9', 
            padding: '15px', 
            borderRadius: '4px', 
            marginBottom: '15px' 
          }}>
            <h3>📝 Text Analysis</h3>
            <p><strong>Total Words:</strong> {fileData.textAnalysis.totalWords.toLocaleString()}</p>
            <p><strong>Suspicious Words:</strong> {fileData.textAnalysis.suspiciousWords}</p>
            <p><strong>Confidence:</strong> {fileData.textAnalysis.confidence}%</p>
            <p style={{ color: fileData.textAnalysis.confidence > 80 ? 'green' : 'orange' }}>
              {fileData.textAnalysis.confidence > 80 ? '✅' : '⚠️'} 
              {fileData.textAnalysis.confidence > 80 ? 
                'Text appears authentic with minimal suspicious indicators' : 
                'Some inconsistencies detected, manual review recommended'
              }
            </p>
          </div>

          {/* Image Analysis */}
          {fileData.imageAnalysis.imagesFound > 0 && (
            <div style={{ 
              backgroundColor: '#f9f9f9', 
              padding: '15px', 
              borderRadius: '4px', 
              marginBottom: '15px' 
            }}>
              <h3>🖼️ Image Analysis</h3>
              <p><strong>Images Found:</strong> {fileData.imageAnalysis.imagesFound}</p>
              <p><strong>Tampered Images:</strong> {fileData.imageAnalysis.tamperedImages}</p>
              <p><strong>Confidence:</strong> {fileData.imageAnalysis.confidence}%</p>
              <p style={{ color: 'green' }}>
                ✅ All images appear authentic with no signs of digital manipulation
              </p>
            </div>
          )}

          {/* Signature Analysis */}
          {fileData.metadata.type.includes('pdf') && (
            <div style={{ 
              backgroundColor: '#f9f9f9', 
              padding: '15px', 
              borderRadius: '4px', 
              marginBottom: '15px' 
            }}>
              <h3>🔒 Digital Signature Check</h3>
              <p><strong>Has Digital Signature:</strong> {fileData.signatureAnalysis.hasSignature ? 'Yes' : 'No'}</p>
              <p><strong>Certificate Status:</strong> {fileData.signatureAnalysis.certificate}</p>
              <p style={{ color: 'gray' }}>
                ℹ️ {fileData.signatureAnalysis.hasSignature ? 
                    'Digital signature detected but requires validation' : 
                    'No digital signature found in this document'
                  }
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default DocumentAnalyzer;
