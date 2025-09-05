import React from "react";
import { FileText, AlertTriangle, CheckCircle } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";

interface TextAnalysisData {
  totalWords: number;
  suspiciousWords: number;
  confidence: number;
  flags: string[];
}

interface TextAnalysisProps {
  data: TextAnalysisData;
}

const TextAnalysis: React.FC<TextAnalysisProps> = ({ data }) => {
  const getConfidenceColor = (confidence: number) => {
    if (confidence >= 90) return "text-green-600";
    if (confidence >= 70) return "text-yellow-600";
    return "text-red-600";
  };

  const getConfidenceMessage = (confidence: number) => {
    if (confidence >= 90) return "Text appears authentic with minimal suspicious indicators";
    if (confidence >= 70) return "Some inconsistencies detected, manual review recommended";
    return "High probability of text manipulation detected";
  };

  const getConfidenceBadgeVariant = (confidence: number) => {
    if (confidence >= 90) return "default";
    if (confidence >= 70) return "secondary";
    return "destructive";
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center space-x-2">
          <FileText className="h-5 w-5" />
          <span>Text Analysis</span>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Confidence Score */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium">Authenticity Confidence</span>
            <Badge variant={getConfidenceBadgeVariant(data.confidence)}>
              {data.confidence}%
            </Badge>
          </div>
          <Progress value={data.confidence} className="h-2" />
          <p className={`text-sm ${getConfidenceColor(data.confidence)}`}>
            {getConfidenceMessage(data.confidence)}
          </p>
        </div>

        {/* Word Analysis */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="space-y-2">
            <div className="text-sm font-medium text-muted-foreground">
              Total Words Analyzed
            </div>
            <div className="text-2xl font-bold">
              {data.totalWords.toLocaleString()}
            </div>
          </div>
          <div className="space-y-2">
            <div className="text-sm font-medium text-muted-foreground">
              Suspicious Elements
            </div>
            <div className="text-2xl font-bold text-red-600">
              {data.suspiciousWords}
            </div>
          </div>
        </div>

        {/* Analysis Summary */}
        <div className="space-y-3">
          <h4 className="font-medium">Analysis Summary</h4>
          {data.suspiciousWords === 0 ? (
            <div className="flex items-center space-x-2 text-green-600">
              <CheckCircle className="h-4 w-4" />
              <span className="text-sm">
                No suspicious text modifications detected. The document appears to maintain its original text integrity.
              </span>
            </div>
          ) : (
            <div className="flex items-center space-x-2 text-yellow-600">
              <AlertTriangle className="h-4 w-4" />
              <span className="text-sm">
                {data.suspiciousWords} potentially suspicious element{data.suspiciousWords > 1 ? 's' : ''} detected out of {data.totalWords.toLocaleString()} total words analyzed.
              </span>
            </div>
          )}
        </div>

        {/* Detected Issues */}
        {data.flags.length > 0 && (
          <div className="space-y-3">
            <h4 className="font-medium">Detected Issues</h4>
            <div className="space-y-2">
              {data.flags.map((flag, index) => (
                <div key={index} className="flex items-center space-x-2">
                  <AlertTriangle className="h-4 w-4 text-yellow-500" />
                  <span className="text-sm">{flag}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Recommendations */}
        {data.confidence < 90 && (
          <div className="space-y-2 p-4 bg-yellow-50 rounded-lg border border-yellow-200">
            <h4 className="font-medium text-yellow-800">Recommendations</h4>
            <ul className="text-sm text-yellow-700 space-y-1">
              {data.confidence < 70 && (
                <li>• Manual review strongly recommended due to high suspicion level</li>
              )}
              {data.suspiciousWords > 0 && (
                <li>• Verify document against original source if available</li>
              )}
              {data.flags.length > 0 && (
                <li>• Check document formatting and encoding for inconsistencies</li>
              )}
            </ul>
          </div>
        )}
      </CardContent>
    </Card>
  );
};

export default TextAnalysis;
