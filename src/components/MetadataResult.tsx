import React, { useState } from "react";
import { FileText, Calendar, User, HardDrive, AlertTriangle, CheckCircle, Eye, EyeOff } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

interface MetadataData {
  filename: string;
  size: number;
  type: string;
  lastModified: string;
  author?: string;
  createdDate?: string;
  modifiedDate?: string;
  pageCount?: number;
}

interface MetadataResultProps {
  data: MetadataData;
  imagePreview?: string | null;
  fileName?: string;
  fileSize?: number;
}

const MetadataResult: React.FC<MetadataResultProps> = ({ 
  data, 
  imagePreview, 
  fileName, 
  fileSize 
}) => {
  const [showImagePreview, setShowImagePreview] = useState(true);

  const formatFileSize = (bytes: number): string => {
    const units = ['B', 'KB', 'MB', 'GB'];
    let size = bytes;
    let unitIndex = 0;

    while (size >= 1024 && unitIndex < units.length - 1) {
      size /= 1024;
      unitIndex++;
    }

    return `${size.toFixed(2)} ${units[unitIndex]}`;
  };

  const formatDate = (dateString: string): string => {
    try {
      return new Date(dateString).toLocaleString();
    } catch {
      return "Invalid date";
    }
  };

  const getFileTypeColor = (type: string): "destructive" | "default" | "secondary" => {
    if (type.includes('pdf')) return 'destructive';
    if (type.includes('word') || type.includes('document')) return 'default';
    return 'secondary';
  };

  const isImageFile = () => {
    return data.type.startsWith('image/') || imagePreview;
  };

  // Metadata integrity check
  const checkMetadataIntegrity = () => {
    const issues: string[] = [];
    const warnings: string[] = [];

    // Check for suspicious author names
    if (data.author && (data.author.toLowerCase() === 'john doe' || data.author.toLowerCase() === 'user')) {
      warnings.push('Generic author name detected');
    }

    // Check date consistency
    if (data.createdDate && data.modifiedDate) {
      const created = new Date(data.createdDate);
      const modified = new Date(data.modifiedDate);
      const lastMod = new Date(data.lastModified);

      if (created > modified) {
        issues.push('Creation date is after modification date');
      }

      if (Math.abs(created.getTime() - modified.getTime()) < 1000) {
        warnings.push('Creation and modification dates are identical');
      }

      if (Math.abs(modified.getTime() - lastMod.getTime()) > 86400000) { // 24 hours
        warnings.push('File system modification date differs significantly from document metadata');
      }
    }

    // Check for missing metadata
    if (!data.author) {
      warnings.push('No author information available');
    }

    if (!data.createdDate) {
      warnings.push('No creation date in metadata');
    }

    return { issues, warnings };
  };

  const { issues, warnings } = checkMetadataIntegrity();

  const metadataFields = [
    {
      icon: FileText,
      label: "Filename",
      value: data.filename,
      type: "text"
    },
    {
      icon: HardDrive,
      label: "File Size",
      value: formatFileSize(data.size),
      type: "text"
    },
    {
      icon: FileText,
      label: "File Type",
      value: data.type,
      type: "badge",
      variant: getFileTypeColor(data.type)
    },
    {
      icon: User,
      label: "Author",
      value: data.author || "Not specified",
      type: "text"
    },
    {
      icon: Calendar,
      label: "Created",
      value: data.createdDate ? formatDate(data.createdDate) : "Not available",
      type: "text"
    },
    {
      icon: Calendar,
      label: "Last Modified",
      value: formatDate(data.lastModified),
      type: "text"
    }
  ];

  if (data.pageCount) {
    metadataFields.splice(3, 0, {
      icon: FileText,
      label: "Pages",
      value: data.pageCount.toString(),
      type: "text"
    });
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center space-x-2">
          <FileText className="h-5 w-5" />
          <span>Document Metadata</span>
          {isImageFile() && (
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setShowImagePreview(!showImagePreview)}
              className="ml-auto"
            >
              {showImagePreview ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              {showImagePreview ? 'Hide Preview' : 'Show Preview'}
            </Button>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Full Image Preview Section */}
        {isImageFile() && showImagePreview && (
          <div className="space-y-3">
            <h4 className="font-medium flex items-center space-x-2">
              <Eye className="h-4 w-4 text-gray-500" />
              <span>📸 Image Preview</span>
            </h4>
            <div className="bg-gray-50 rounded-lg p-4 border border-gray-200">
              <div className="text-center">
                <div className="w-full max-w-lg mx-auto">
                  {imagePreview ? (
                    // Real Image Preview
                    <div className="space-y-3">
                      <img
                        src={imagePreview}
                        alt={fileName || data.filename}
                        className="w-full h-auto max-h-80 object-contain rounded-lg border border-gray-300 bg-white shadow-sm"
                      />
                      <div className="text-sm text-gray-600 space-y-1">
                        <p className="font-medium">{fileName || data.filename}</p>
                        <p className="text-xs text-gray-500">
                          {fileSize ? formatFileSize(fileSize) : formatFileSize(data.size)}
                        </p>
                      </div>
                    </div>
                  ) : (
                    // Placeholder for non-image files or when preview isn't available
                    <div className="aspect-video bg-gradient-to-br from-blue-100 to-purple-100 rounded-lg flex items-center justify-center border">
                      <div className="text-center text-gray-600">
                        <FileText className="w-12 h-12 mx-auto mb-2 text-gray-400" />
                        <p className="text-sm">Image Preview</p>
                        <p className="text-xs text-gray-500 mt-1">
                          {fileName || data.filename}
                        </p>
                        <p className="text-xs text-gray-400">
                          {fileSize ? formatFileSize(fileSize) : formatFileSize(data.size)}
                        </p>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Metadata Fields */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {metadataFields.map((field, index) => (
            <div key={index} className="flex items-center space-x-3">
              <field.icon className="h-4 w-4 text-muted-foreground" />
              <div className="flex-1">
                <div className="text-sm font-medium text-muted-foreground">
                  {field.label}
                </div>
                {field.type === 'badge' ? (
                  <Badge variant={field.variant as any}>
                    {field.value}
                  </Badge>
                ) : (
                  <div className="text-sm">{field.value}</div>
                )}
              </div>
            </div>
          ))}
        </div>

        {/* Metadata Integrity Check */}
        <div className="space-y-3">
          <h4 className="font-medium">Metadata Integrity</h4>
          
          {issues.length === 0 && warnings.length === 0 && (
            <div className="flex items-center space-x-2 text-green-600">
              <CheckCircle className="h-4 w-4" />
              <span className="text-sm">No suspicious metadata modifications detected</span>
            </div>
          )}

          {issues.map((issue, index) => (
            <div key={`issue-${index}`} className="flex items-center space-x-2 text-red-600">
              <AlertTriangle className="h-4 w-4" />
              <span className="text-sm">{issue}</span>
            </div>
          ))}

          {warnings.map((warning, index) => (
            <div key={`warning-${index}`} className="flex items-center space-x-2 text-yellow-600">
              <AlertTriangle className="h-4 w-4" />
              <span className="text-sm">{warning}</span>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
};

export default MetadataResult;
