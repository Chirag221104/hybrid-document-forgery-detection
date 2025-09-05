import * as pdfjsLib from "pdfjs-dist";
import workerSrc from "pdfjs-dist/build/pdf.worker.min.mjs?url";

// Configure worker for Vite
(pdfjsLib as any).GlobalWorkerOptions.workerSrc = workerSrc;

export const extractPdfMetadata = async (file: File) => {
  try {
    const buffer = await file.arrayBuffer();
    const pdf = await (pdfjsLib as any).getDocument({ data: buffer }).promise;

    let meta: any = {};
    try {
      meta = await pdf.getMetadata();
    } catch (err) {
      console.warn("No metadata found in PDF:", err);
    }

    return {
      author: meta?.info?.Author || "Unknown",
      title: meta?.info?.Title || "Untitled",
      subject: meta?.info?.Subject || null,
      createdDate: meta?.info?.CreationDate || null,
      modifiedDate: meta?.info?.ModDate || null,
    };
  } catch (error) {
    console.error("Failed to extract PDF metadata:", error);
    return {
      author: "Unknown",
      title: "Untitled",
      subject: null,
      createdDate: null,
      modifiedDate: null,
    };
  }
};
