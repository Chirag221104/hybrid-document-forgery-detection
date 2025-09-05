import { useState } from "react";
import { Upload, FileText, Shield, CheckCircle, AlertTriangle, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { useToast } from "@/hooks/use-toast";
import UploadForm from "@/components/UploadForm";
import MetadataResult from "@/components/MetadataResult";
import TextAnalysis from "@/components/TextAnalysis";
import ImageAnalysis from "@/components/ImageAnalysis";
import SignatureCheck from "@/components/SignatureCheck";

interface AnalysisResults {
  metadata?: any;
  textAnalysis?: any;
  imageAnalysis?: any;
  signatureCheck?: any;
}

const Index = () => {
  const [file, setFile] = useState<File | null>(null);
  const [imagePreview, setImagePreview] = useState<string | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [results, setResults] = useState<AnalysisResults | null>(null);
  const [analysisProgress, setAnalysisProgress] = useState(0);
  const [currentAnalysisStep, setCurrentAnalysisStep] = useState("");
  const { toast } = useToast();

  const handleFileSelect = (selectedFile: File, preview?: string) => {
    console.log('File selected:', selectedFile.name);
    setFile(selectedFile);
    setImagePreview(preview || null);
    setResults(null);
    setAnalysisProgress(0);
    setCurrentAnalysisStep("");
  };

  const handleAnalyze = async () => {
    if (!file) {
      toast({
        title: "No file selected",
        description: "Please select a file to analyze",  
        variant: "destructive",
      });
      return;
    }

    console.log('Starting backend analysis for:', file.name);
    setIsAnalyzing(true);
    setAnalysisProgress(0);

    // Enhanced progress simulation with detailed steps
    const progressSteps = [
      { progress: 10, message: "Initializing analysis...", delay: 300 },
      { progress: 25, message: "Uploading file to server...", delay: 500 },
      { progress: 40, message: "Extracting document metadata...", delay: 700 },
      { progress: 60, message: "Analyzing text content...", delay: 600 },
      { progress: 75, message: "Checking images and signatures...", delay: 500 },
      { progress: 90, message: "Generating analysis report...", delay: 400 },
      { progress: 100, message: "Analysis complete!", delay: 200 }
    ];

    let currentStepIndex = 0;
    const progressInterval = setInterval(() => {
      if (currentStepIndex < progressSteps.length) {
        const step = progressSteps[currentStepIndex];
        setAnalysisProgress(step.progress);
        setCurrentAnalysisStep(step.message);
        currentStepIndex++;
      } else {
        clearInterval(progressInterval);
      }
    }, 600);

    try {
      const formData = new FormData();
      formData.append("file", file);

      // **BULLETPROOF FIX: Always use production URL when deployed**
      const isProduction = window.location.hostname !== 'localhost' && window.location.hostname !== '127.0.0.1';
      const apiUrl = isProduction 
        ? "https://hybrid-document-forgery-detection-opap36ow2.vercel.app"
        : "http://localhost:8000";

      console.log('🌍 Current hostname:', window.location.hostname);
      console.log('🚀 Is Production:', isProduction);
      console.log('🔗 API URL being used:', apiUrl);
      console.log('🎯 Full request URL:', `${apiUrl}/api/analyze`);

      // Call FastAPI backend with explicit URL
      const response = await fetch(`${apiUrl}/api/analyze`, {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.detail || `Server error: ${response.status}`);
      }

      const data = await response.json();
      console.log('✅ Backend response received:', data);

      // Ensure we reach 100%
      clearInterval(progressInterval);
      setAnalysisProgress(100);
      setCurrentAnalysisStep("Analysis complete!");

      // Set results from backend
      setResults({
        metadata: data.metadata,
        textAnalysis: data.textAnalysis,
        imageAnalysis: data.imageAnalysis,
        signatureCheck: data.signatureCheck,
      });

      toast({
        title: "Analysis Complete",
        description: "Document analysis completed successfully with real metadata extraction",
      });

    } catch (error) {
      console.error('❌ Backend analysis error:', error);
      clearInterval(progressInterval);
      setAnalysisProgress(0);
      setCurrentAnalysisStep("");
      
      const isProduction = window.location.hostname !== 'localhost' && window.location.hostname !== '127.0.0.1';
      const apiUrl = isProduction 
        ? "https://hybrid-document-forgery-detection-opap36ow2.vercel.app"
        : "http://localhost:8000";
      
      let errorMessage = "Failed to analyze document. Please try again.";
      
      if (error instanceof Error) {
        if (error.message.includes('Failed to fetch')) {
          errorMessage = `❌ Cannot connect to backend at ${apiUrl}. Backend may be down or there's a network issue.`;
        } else {
          errorMessage = error.message;
        }
      }

      toast({
        title: "Analysis Failed",
        description: errorMessage,
        variant: "destructive",
      });
    } finally {
      setTimeout(() => {
        setIsAnalyzing(false);
        setAnalysisProgress(0);
        setCurrentAnalysisStep("");
      }, 1000);
    }
  };

  return (
    <div className="min-h-screen bg-background">
      <main className="container mx-auto px-4 py-8">
        {/* Header */}
        <div className="text-center mb-12">
          <div className="flex items-center justify-center mb-6">
            <div className="p-3 rounded-full bg-gradient-to-r from-primary to-primary-hover mr-4">
              <Shield className="w-8 h-8 text-primary-foreground" />
            </div>
            <h1 className="text-4xl font-bold bg-gradient-to-r from-primary to-primary-hover bg-clip-text text-transparent">
              Hybrid Document Forgery Detection
            </h1>
          </div>
          <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
            Advanced AI-powered analysis to detect document tampering, verify authenticity, and ensure integrity
          </p>
        </div>

        {/* Upload Section */}
        <Card className="mb-8 shadow-[var(--shadow-card)]">
          <CardHeader>
            <CardTitle className="flex items-center">
              <Upload className="w-5 h-5 mr-2" />
              Upload Document
            </CardTitle>
          </CardHeader>
          <CardContent>
            <UploadForm onFileSelect={handleFileSelect} />
            {file && (
              <div className="mt-6 p-4 bg-secondary/50 rounded-lg">
                <div className="flex items-center justify-between">
                  <div className="flex items-center">
                    <FileText className="w-5 h-5 text-primary mr-2" />
                    <div>
                      <p className="font-medium">{file.name}</p>
                      <p className="text-sm text-muted-foreground">
                        {(file.size / 1024 / 1024).toFixed(2)} MB
                      </p>
                    </div>
                  </div>
                  <Button 
                    onClick={handleAnalyze} 
                    disabled={isAnalyzing}
                    className="bg-gradient-to-r from-primary to-primary-hover hover:opacity-90 transition-opacity min-w-[160px]"
                  >
                    {isAnalyzing ? (
                      <>
                        <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                        Analyzing...
                      </>
                    ) : (
                      <>
                        <Shield className="w-4 h-4 mr-2" />
                        Analyze Document
                      </>
                    )}
                  </Button>
                </div>
                
                {/* Inline Progress Bar (appears when analyzing) */}
                {isAnalyzing && (
                  <div className="mt-4 space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-medium text-primary">Processing...</span>
                      <span className="text-sm font-bold text-primary">{analysisProgress}%</span>
                    </div>
                    <Progress value={analysisProgress} className="w-full h-2" />
                    <div className="flex items-center space-x-2">
                      <Loader2 className="w-3 h-3 animate-spin text-primary" />
                      <p className="text-xs text-muted-foreground">{currentAnalysisStep}</p>
                    </div>
                  </div>
                )}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Main Progress Section (Enhanced) */}
        {isAnalyzing && (
          <Card className="mb-8 border-primary/20 shadow-lg">
            <CardHeader className="pb-4">
              <CardTitle className="flex items-center text-primary">
                <Loader2 className="w-5 h-5 mr-2 animate-spin" />
                Document Analysis in Progress
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-6">
              {/* Main Progress Bar */}
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-lg font-semibold">Analysis Progress</span>
                  <span className="text-2xl font-bold text-primary">{analysisProgress}%</span>
                </div>
                <Progress 
                  value={analysisProgress} 
                  className="w-full h-4 bg-gray-200"
                />
                <div className="flex items-center space-x-3">
                  <Loader2 className="w-5 h-5 animate-spin text-primary" />
                  <p className="text-base font-medium text-foreground">
                    {currentAnalysisStep}
                  </p>
                </div>
              </div>

              {/* Analysis Steps Checklist */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-3">
                  <h4 className="font-semibold text-sm uppercase tracking-wide text-muted-foreground">Analysis Steps</h4>
                  {[
                    { step: "File Upload", completed: analysisProgress > 10 },
                    { step: "Metadata Extraction", completed: analysisProgress > 40 },
                    { step: "Content Analysis", completed: analysisProgress > 60 },
                    { step: "Report Generation", completed: analysisProgress > 90 }
                  ].map((item, index) => (
                    <div key={index} className="flex items-center space-x-2">
                      {item.completed ? (
                        <CheckCircle className="w-4 h-4 text-green-500" />
                      ) : (
                        <div className="w-4 h-4 rounded-full border-2 border-gray-300" />
                      )}
                      <span className={`text-sm ${item.completed ? 'text-green-600 font-medium' : 'text-muted-foreground'}`}>
                        {item.step}
                      </span>
                    </div>
                  ))}
                </div>
                
                <div className="space-y-3">
                  <h4 className="font-semibold text-sm uppercase tracking-wide text-muted-foreground">Processing</h4>
                  <div className="text-sm space-y-1">
                    <div>📄 Document Type: {file?.type || 'Unknown'}</div>
                    <div>📏 File Size: {file ? (file.size / 1024 / 1024).toFixed(2) : '0'} MB</div>
                    <div>⏱️ Estimated Time: ~10 seconds</div>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Results Section */}
        {results && (
          <div className="grid gap-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <MetadataResult 
                data={results.metadata}
                imagePreview={imagePreview}
                fileName={file?.name}
                fileSize={file?.size}
              />
              <TextAnalysis data={results.textAnalysis} />
            </div>
            
            {/* Only show ImageAnalysis if images are actually found */}
            {results.imageAnalysis && (
              <ImageAnalysis data={results.imageAnalysis} />
            )}
            
            {/* Only show SignatureCheck for PDFs */}
            {results.signatureCheck && results.metadata && results.metadata.type.includes('pdf') && (
              <SignatureCheck data={results.signatureCheck} />
            )}
          </div>
        )}
          
        {/* Features Overview */}
        {!results && !isAnalyzing && (
          <div className="mt-16 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            {[
              {
                icon: FileText,
                title: "Metadata Analysis",
                description: "Extract and analyze real document metadata for inconsistencies"
              },
              {
                icon: Shield,
                title: "Text Verification",
                description: "Detect text-based forgeries and suspicious modifications"
              },
              {
                icon: CheckCircle,
                title: "Image Analysis",
                description: "Identify tampered images and suspicious regions in PDFs"
              },
              {
                icon: AlertTriangle,  
                title: "Digital Signatures",
                description: "Verify digital signatures and certificate validity"
              }
            ].map((feature, index) => (
              <Card key={index} className="text-center hover:shadow-lg transition-shadow">
                <CardContent className="pt-6">
                  <div className="w-12 h-12 bg-primary/10 rounded-lg flex items-center justify-center mx-auto mb-4">
                    <feature.icon className="w-6 h-6 text-primary" />
                  </div>
                  <h3 className="font-semibold mb-2">{feature.title}</h3>
                  <p className="text-sm text-muted-foreground">{feature.description}</p>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </main>
    </div>
  );
};

export default Index;
