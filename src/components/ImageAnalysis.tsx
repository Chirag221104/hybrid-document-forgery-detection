import React, { useState } from "react";
import { Image, AlertTriangle, CheckCircle, Eye, EyeOff } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

interface ImageAnalysisData {
  imagesFound: number;
  tamperedImages: number;
  confidence: number;
  suspiciousRegions: string[];
  imageDetails?: Array<{
    page: number;
    name: string;
    width: number;
    height: number;
    format: string;
    size: number;
  }>;
}

interface ImageAnalysisProps {
  data: ImageAnalysisData;
}

const ImageAnalysis: React.FC<ImageAnalysisProps> = ({ data }) => {
  
  const getConfidenceColor = (confidence: number) => {
    if (confidence >= 90) return "text-green-600";
    if (confidence >= 70) return "text-yellow-600";
    return "text-red-600";
  };

  const getConfidenceBadgeVariant = (confidence: number) => {
    if (confidence >= 90) return "default";
    if (confidence >= 70) return "secondary";
    return "destructive";
  };

  const getAnalysisMessage = () => {
    if (data.imagesFound === 0) {
      return "No images detected in this document.";
    }
    
    if (data.tamperedImages === 0) {
      return `All ${data.imagesFound} image${data.imagesFound > 1 ? 's' : ''} appear authentic with no signs of digital manipulation. Image forensics analysis shows consistent compression artifacts and metadata.`;
    }
    
    return `${data.tamperedImages} out of ${data.imagesFound} image${data.imagesFound > 1 ? 's' : ''} show signs of potential tampering. Anomalies detected in pixel patterns, compression artifacts, and metadata consistency.`;
  };

  // Only show component if images are found
  if (data.imagesFound === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Image className="h-5 w-5" />
            <span>Image Analysis</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center space-x-2 text-muted-foreground">
            <Eye className="h-4 w-4" />
            <span className="text-sm">No images detected in this document for analysis.</span>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center space-x-2">
          <Image className="h-5 w-5" />
          <span>Image Analysis</span>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Confidence Score */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium">Image Authenticity</span>
            <Badge variant={getConfidenceBadgeVariant(data.confidence)}>
              {data.confidence}%
            </Badge>
          </div>
          <Progress value={data.confidence} className="h-2" />
          {data.confidence < 70 && (
            <div className="flex items-center space-x-2 text-yellow-600">
              <AlertTriangle className="h-4 w-4" />
              <span className="text-sm">Low confidence score indicates possible image manipulation</span>
            </div>
          )}
        </div>

        {/* Image Statistics */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="space-y-2">
            <div className="text-sm font-medium text-muted-foreground">
              Images Found
            </div>
            <div className="text-2xl font-bold text-blue-600">
              {data.imagesFound}
            </div>
          </div>
          <div className="space-y-2">
            <div className="text-sm font-medium text-muted-foreground">
              Potentially Tampered
            </div>
            <div className={`text-2xl font-bold ${data.tamperedImages > 0 ? 'text-red-600' : 'text-green-600'}`}>
              {data.tamperedImages}
            </div>
          </div>
        </div>

        {/* Real Image Details (only if backend provides them) */}
        {data.imageDetails && data.imageDetails.length > 0 && (
          <div className="space-y-4">
            <h4 className="font-medium flex items-center space-x-2">
              <Image className="h-4 w-4" />
              <span>🖼️ Images Found in Document</span>
            </h4>
            
            <div className="space-y-3">
              {data.imageDetails.map((img, index) => (
                <div key={index} className="bg-gray-50 rounded-lg p-4 border border-gray-200">
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div>
                      <span className="font-medium">📄 Page:</span> {img.page}
                    </div>
                    <div>
                      <span className="font-medium">📐 Dimensions:</span> {img.width}x{img.height}
                    </div>
                    <div>
                      <span className="font-medium">🖼️ Format:</span> {img.format}
                    </div>
                    <div>
                      <span className="font-medium">📏 Size:</span> {(img.size / 1024).toFixed(1)} KB
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Analysis Summary */}
        <div className="space-y-3">
          <h4 className="font-medium">Analysis Summary</h4>
          <div className={`flex items-start space-x-2 ${data.tamperedImages === 0 ? 'text-green-600' : 'text-yellow-600'}`}>
            {data.tamperedImages === 0 ? (
              <CheckCircle className="h-4 w-4 mt-0.5" />
            ) : (
              <AlertTriangle className="h-4 w-4 mt-0.5" />
            )}
            <span className="text-sm">
              {getAnalysisMessage()}
            </span>
          </div>
        </div>

        {/* Suspicious Regions */}
        {data.suspiciousRegions.length > 0 && (
          <div className="space-y-3">
            <h4 className="font-medium">Suspicious Regions</h4>
            <div className="space-y-2">
              {data.suspiciousRegions.map((region, index) => (
                <div key={index} className="flex items-center space-x-2">
                  <AlertTriangle className="h-4 w-4 text-red-500" />
                  <span className="text-sm">{region}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Forensics Details */}
        <div className="space-y-2 p-4 bg-blue-50 rounded-lg border border-blue-200">
          <h4 className="font-medium text-blue-800">Forensics Techniques Applied</h4>
          <ul className="text-sm text-blue-700 space-y-1">
            <li>• Real PDF image extraction analysis</li>
            <li>• Metadata consistency check</li>
            <li>• File structure integrity verification</li>
            <li>• XObject analysis for embedded images</li>
          </ul>
        </div>
      </CardContent>
    </Card>
  );
};

export default ImageAnalysis;
