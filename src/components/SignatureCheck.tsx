import React, { useState } from "react";
import { Shield, CheckCircle, XCircle, AlertTriangle, FileX, Key, Calendar, User, Award, ChevronDown, ChevronUp } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";

interface SignatureData {
  hasDigitalSignature: boolean;
  isValid: boolean;
  signerName: string;
  signedDate: string;
  certificate: string;
}

interface SignatureCheckProps {
  data: SignatureData;
}

const SignatureCheck: React.FC<SignatureCheckProps> = ({ data }) => {
  const [showDetails, setShowDetails] = useState(false);

  const getSignatureStatus = () => {
    if (!data.hasDigitalSignature) {
      return {
        icon: FileX,
        color: "text-gray-600",
        bgColor: "bg-gray-50",
        borderColor: "border-gray-200",
        badge: "No Signature",
        badgeVariant: "secondary" as const,
        title: "No Digital Signature",
        description: "This document does not contain a digital signature."
      };
    }

    if (data.isValid) {
      return {
        icon: CheckCircle,
        color: "text-green-600",
        bgColor: "bg-green-50",
        borderColor: "border-green-200",
        badge: "Valid",
        badgeVariant: "default" as const,
        title: "Valid Digital Signature",
        description: "The digital signature is valid and the document has not been tampered with since signing."
      };
    }

    return {
      icon: XCircle,
      color: "text-red-600",
      bgColor: "bg-red-50",
      borderColor: "border-red-200",
      badge: "Invalid",
      badgeVariant: "destructive" as const,
      title: "Invalid Digital Signature",
      description: "The digital signature is invalid. The document may have been modified after signing or the signature is corrupted."
    };
  };

  const formatDate = (dateString: string): string => {
    if (!dateString) return "Not available";
    try {
      return new Date(dateString).toLocaleString();
    } catch {
      return "Invalid date";
    }
  };

  const getCertificateStatus = () => {
    const cert = data.certificate.toLowerCase();
    if (cert.includes('expired')) {
      return {
        icon: AlertTriangle,
        color: "text-yellow-600",
        bgColor: "bg-yellow-50",
        message: "The certificate used to sign this document has expired. While the signature may have been valid at signing time, current validation fails."
      };
    }
    
    if (cert.includes('revoked')) {
      return {
        icon: XCircle,
        color: "text-red-600",
        bgColor: "bg-red-50",
        message: "The certificate has been revoked by the issuing authority. This signature should not be trusted."
      };
    }
    
    if (cert.includes('valid')) {
      return {
        icon: CheckCircle,
        color: "text-green-600",
        bgColor: "bg-green-50",
        message: "Certificate is valid and trusted by the certification authority."
      };
    }

    if (cert.includes('not applicable')) {
      return {
        icon: FileX,
        color: "text-gray-600",
        bgColor: "bg-gray-50",
        message: "Certificate validation is not applicable for this file type."
      };
    }
    
    return {
      icon: AlertTriangle,
      color: "text-yellow-600",
      bgColor: "bg-yellow-50",
      message: "Certificate status requires manual verification with the issuing authority."
    };
  };

  const signatureStatus = getSignatureStatus();
  const certificateStatus = getCertificateStatus();

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center space-x-2">
          <Shield className="h-5 w-5" />
          <span>Digital Signature Check</span>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Signature Status */}
        <div className={`p-4 rounded-lg ${signatureStatus.bgColor} border ${signatureStatus.borderColor}`}>
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center space-x-2">
              <signatureStatus.icon className={`h-5 w-5 ${signatureStatus.color}`} />
              <h4 className={`font-medium ${signatureStatus.color}`}>
                {signatureStatus.title}
              </h4>
            </div>
            <Badge variant={signatureStatus.badgeVariant}>
              {signatureStatus.badge}
            </Badge>
          </div>
          <p className={`text-sm ${signatureStatus.color}`}>
            {signatureStatus.description}
          </p>
        </div>

        {/* Digital Signature Visualization */}
        {data.hasDigitalSignature && (
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <h4 className="font-medium">🔐 Digital Signature Details</h4>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setShowDetails(!showDetails)}
              >
                {showDetails ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                {showDetails ? 'Hide Details' : 'Show Details'}
              </Button>
            </div>

            {/* Signature Visual Representation */}
            <div className="bg-gradient-to-r from-blue-50 to-purple-50 rounded-lg p-6 border-2 border-dashed border-blue-200">
              <div className="text-center">
                <div className="w-16 h-16 mx-auto mb-4 bg-blue-100 rounded-full flex items-center justify-center">
                  <Key className="w-8 h-8 text-blue-600" />
                </div>
                <div className="space-y-2">
                  <div className="text-lg font-semibold text-gray-800">
                    Digital Signature Present
                  </div>
                  <div className="text-sm text-gray-600">
                    Cryptographic signature found in document
                  </div>
                  <div className={`inline-flex items-center px-3 py-1 rounded-full text-xs font-medium ${
                    data.isValid 
                      ? 'bg-green-100 text-green-800' 
                      : 'bg-red-100 text-red-800'
                  }`}>
                    {data.isValid ? '✅ Signature Valid' : '❌ Signature Invalid'}
                  </div>
                </div>
              </div>
            </div>

            {/* Signature Information Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-3">
                <div className="flex items-center space-x-2">
                  <User className="w-4 w-4 text-gray-500" />
                  <div>
                    <div className="text-sm font-medium text-muted-foreground">Signer Name</div>
                    <div className="text-sm font-semibold">{data.signerName}</div>
                  </div>
                </div>
                
                <div className="flex items-center space-x-2">
                  <Calendar className="w-4 h-4 text-gray-500" />
                  <div>
                    <div className="text-sm font-medium text-muted-foreground">Signed Date</div>
                    <div className="text-sm">{formatDate(data.signedDate)}</div>
                  </div>
                </div>
              </div>

              <div className="space-y-3">
                <div className="flex items-center space-x-2">
                  <Award className="w-4 h-4 text-gray-500" />
                  <div>
                    <div className="text-sm font-medium text-muted-foreground">Certificate Status</div>
                    <div className={`text-sm font-semibold ${certificateStatus.color}`}>
                      {data.certificate}
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Collapsible Technical Details */}
            <Collapsible open={showDetails} onOpenChange={setShowDetails}>
              <CollapsibleContent className="space-y-4">
                <div className="border-t pt-4">
                  <h5 className="font-medium mb-3">🔧 Technical Details</h5>
                  <div className="bg-gray-50 rounded-lg p-4 space-y-2">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                      <div>
                        <span className="font-medium">Signature Algorithm:</span>
                        <div className="text-gray-600 mt-1">RSA-SHA256 (Simulated)</div>
                      </div>
                      <div>
                        <span className="font-medium">Hash Algorithm:</span>
                        <div className="text-gray-600 mt-1">SHA-256</div>
                      </div>
                      <div>
                        <span className="font-medium">Key Size:</span>
                        <div className="text-gray-600 mt-1">2048-bit</div>
                      </div>
                      <div>
                        <span className="font-medium">Timestamp:</span>
                        <div className="text-gray-600 mt-1">
                          {data.signedDate ? 'Present' : 'Not Available'}
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </CollapsibleContent>
            </Collapsible>

            {/* Certificate Status Details */}
            <div className={`p-3 rounded-lg border ${certificateStatus.bgColor}`}>
              <div className="flex items-start space-x-2">
                <certificateStatus.icon className={`h-4 w-4 mt-0.5 ${certificateStatus.color}`} />
                <p className={`text-sm ${certificateStatus.color}`}>
                  {certificateStatus.message}
                </p>
              </div>
            </div>
          </div>
        )}

        {/* No Signature Message */}
        {!data.hasDigitalSignature && (
          <div className="space-y-4">
            <div className="bg-gradient-to-r from-gray-50 to-blue-50 rounded-lg p-6 border-2 border-dashed border-gray-200">
              <div className="text-center">
                <div className="w-16 h-16 mx-auto mb-4 bg-gray-100 rounded-full flex items-center justify-center">
                  <FileX className="w-8 h-8 text-gray-500" />
                </div>
                <div className="space-y-2">
                  <div className="text-lg font-semibold text-gray-600">
                    No Digital Signature Found
                  </div>
                  <div className="text-sm text-gray-500">
                    This document does not contain any cryptographic signatures
                  </div>
                </div>
              </div>
            </div>

            <div className="p-4 bg-blue-50 rounded-lg border border-blue-200">
              <h4 className="font-medium text-blue-800 mb-2">💡 Security Recommendation</h4>
              <p className="text-sm text-blue-700">
                Consider adding a digital signature to verify document authenticity and integrity. 
                Digital signatures help ensure that the document hasn't been tampered with and verify the identity of the signer.
              </p>
            </div>
          </div>
        )}

        {/* Trust Indicators */}
        {data.hasDigitalSignature && (
          <div className="space-y-2">
            <h4 className="font-medium">🛡️ Trust Indicators</h4>
            <div className="space-y-2">
              <div className="flex items-center space-x-2">
                {data.isValid ? (
                  <CheckCircle className="h-4 w-4 text-green-600" />
                ) : (
                  <XCircle className="h-4 w-4 text-red-600" />
                )}
                <span className="text-sm">
                  Document integrity: {data.isValid ? 'Verified' : 'Compromised'}
                </span>
              </div>
              
              <div className="flex items-center space-x-2">
                {data.certificate.toLowerCase().includes('valid') ? (
                  <CheckCircle className="h-4 w-4 text-green-600" />
                ) : (
                  <AlertTriangle className="h-4 w-4 text-yellow-600" />
                )}
                <span className="text-sm">
                  Certificate validity: {data.certificate}
                </span>
              </div>

              <div className="flex items-center space-x-2">
                {data.signerName && data.signerName !== 'No signature found' ? (
                  <CheckCircle className="h-4 w-4 text-green-600" />
                ) : (
                  <XCircle className="h-4 w-4 text-red-600" />
                )}
                <span className="text-sm">
                  Signer identity: {data.signerName && data.signerName !== 'No signature found' ? 'Identified' : 'Unknown'}
                </span>
              </div>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
};

export default SignatureCheck;
