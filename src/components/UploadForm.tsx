import React, { useCallback, useState, useEffect } from "react";
import { useDropzone } from "react-dropzone";
import { Button } from "@/components/ui/button";
import { Upload, FileText, X, CheckCircle2, Eye } from "lucide-react";

interface UploadFormProps {
  onFileSelect: (file: File, imagePreview?: string) => void;
}

const UploadForm = ({ onFileSelect }: UploadFormProps) => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [imagePreview, setImagePreview] = useState<string | null>(null);

  const onDrop = useCallback((acceptedFiles: File[]) => {
    if (acceptedFiles.length > 0) {
      const file = acceptedFiles[0];
      setSelectedFile(file);

      // Create preview for image files
      if (file.type.startsWith('image/')) {
        const reader = new FileReader();
        reader.onloadend = () => {
          const preview = reader.result as string;
          setImagePreview(preview);
          onFileSelect(file, preview); // Pass both file and preview
        };
        reader.readAsDataURL(file);
      } else {
        setImagePreview(null);
        onFileSelect(file); // Pass only file for non-images
      }
    }
  }, [onFileSelect]);

  const { getRootProps, getInputProps, isDragActive, isDragReject } = useDropzone({
    onDrop,
    accept: {
      'application/pdf': ['.pdf'],
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['.docx'],
      'application/msword': ['.doc'],
      'image/png': ['.png'],
      'image/jpeg': ['.jpg', '.jpeg'],
      'text/plain': ['.txt']
    },
    maxFiles: 1,
    maxSize: 50 * 1024 * 1024, // 50MB
    multiple: false
  });

  const removeFile = () => {
    setSelectedFile(null);
    setImagePreview(null);
  };

  // Cleanup object URL on unmount
  useEffect(() => {
    return () => {
      if (imagePreview && imagePreview.startsWith('blob:')) {
        URL.revokeObjectURL(imagePreview);
      }
    };
  }, [imagePreview]);

  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const getFileIcon = (type: string) => {
    if (type.includes('pdf')) return '📄';
    if (type.includes('word') || type.includes('document')) return '📝';
    if (type.includes('image')) return '🖼️';
    return '📋';
  };

  return (
    <div className="w-full space-y-4">
      {/* Drag and Drop Area */}
      <div
        {...getRootProps()}
        className={`
          relative border-2 border-dashed rounded-lg p-8 text-center cursor-pointer transition-all duration-300
          ${isDragActive && !isDragReject 
            ? 'border-primary bg-primary/10 scale-[1.02] shadow-lg' 
            : isDragReject 
            ? 'border-red-500 bg-red-50 scale-[1.02]' 
            : 'border-gray-300 hover:border-primary hover:bg-gray-50'
          }
        `}
      >
        <input {...getInputProps()} />
        
        {/* Main Content - Hidden when dragging */}
        <div className={`flex flex-col items-center space-y-4 transition-opacity duration-200 ${
          isDragActive ? 'opacity-0' : 'opacity-100'
        }`}>
          {/* Upload Icon */}
          <div className="p-4 bg-blue-50 text-primary rounded-full">
            <Upload className="w-8 h-8" />
          </div>
          
          {/* Static Text */}
          <div>
            <h3 className="text-lg font-medium text-gray-900">
              {selectedFile 
                ? '✅ File selected - drag another to replace' 
                : '📤 Drag & Drop your document here'
              }
            </h3>
            <p className="text-sm text-gray-500 mt-1">
              Supported: PDF, Word (.docx), Images (PNG, JPG), Text files
            </p>
            <p className="text-xs text-gray-400 mt-1">
              Maximum file size: 50MB
            </p>
          </div>
          
          {/* Click to Browse Button */}
          {!selectedFile && (
            <Button 
              variant="outline" 
              className="mt-4 bg-white hover:bg-gray-50"
              onClick={(e) => e.stopPropagation()}
            >
              <FileText className="w-4 h-4 mr-2" />
              Or click to browse files
            </Button>
          )}
        </div>

        {/* Drag Overlay - Only shows when dragging */}
        {isDragActive && (
          <div className="absolute inset-0 bg-white/95 backdrop-blur-sm rounded-lg flex flex-col items-center justify-center">
            <div className={`text-center transition-all duration-200 ${
              isDragReject ? 'text-red-600' : 'text-primary'
            }`}>
              <div className={`text-6xl mb-4 animate-bounce ${
                isDragReject ? '' : 'animate-pulse'
              }`}>
                {isDragReject ? '❌' : '🎯'}
              </div>
              <div className="text-2xl font-bold mb-2">
                {isDragReject ? 'Invalid file type!' : 'Drop your file here!'}
              </div>
              <div className="text-sm opacity-75">
                {isDragReject 
                  ? 'Please select a supported file type' 
                  : 'Release to upload your document'
                }
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Selected File Preview */}
      {selectedFile && (
        <div className="bg-gray-50 rounded-lg p-4 border border-gray-200">
          <div className="flex items-start justify-between">
            <div className="flex items-start space-x-3">
              <div className="text-2xl">
                {getFileIcon(selectedFile.type)}
              </div>
              <div className="flex-1">
                <p className="font-medium text-gray-900 truncate max-w-xs">
                  {selectedFile.name}
                </p>
                <p className="text-sm text-gray-500">
                  {formatFileSize(selectedFile.size)} • {selectedFile.type.split('/')[1]?.toUpperCase() || 'Unknown'}
                </p>
                
                {/* Small Thumbnail Preview */}
                {imagePreview && (
                  <div className="mt-3">
                    <div className="flex items-center space-x-2 mb-2">
                      <Eye className="w-4 h-4 text-gray-500" />
                      <span className="text-sm text-gray-600 font-medium">Quick Preview</span>
                    </div>
                    <div className="relative">
                      <img
                        src={imagePreview}
                        alt={selectedFile.name}
                        className="w-20 h-20 object-cover rounded-lg border border-gray-200 shadow-sm"
                      />
                    </div>
                    <p className="text-xs text-gray-500 mt-1">
                      Full preview available in analysis results
                    </p>
                  </div>
                )}
              </div>
            </div>
            
            <div className="flex items-center space-x-2">
              <CheckCircle2 className="w-5 h-5 text-green-500" />
              <Button
                variant="ghost"
                size="sm"
                onClick={removeFile}
                className="text-red-500 hover:text-red-700 hover:bg-red-50"
              >
                <X className="w-4 h-4" />
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* File Type Guide */}
      <div className="bg-blue-50 rounded-lg p-4 border border-blue-200">
        <h4 className="text-sm font-medium text-blue-900 mb-2">📋 Supported File Types:</h4>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs text-blue-700">
          <div className="flex items-center space-x-1">
            <span>📄</span>
            <span>PDF Documents</span>
          </div>
          <div className="flex items-center space-x-1">
            <span>📝</span>
            <span>Word Files (.docx)</span>
          </div>
          <div className="flex items-center space-x-1">
            <span>🖼️</span>
            <span>Images (PNG, JPG)</span>
          </div>
          <div className="flex items-center space-x-1">
            <span>📋</span>
            <span>Text Files (.txt)</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default UploadForm;
