import JSZip from "jszip";

export const extractDocxMetadata = async (file: File) => {
  const buffer = await file.arrayBuffer();
  const zip = await JSZip.loadAsync(buffer);
  const coreXml = await zip.file("docProps/core.xml")?.async("string");
  if (!coreXml) return {};

  const parser = new DOMParser();
  const xml = parser.parseFromString(coreXml, "application/xml");

  const getTag = (tag: string) =>
    xml.getElementsByTagName(tag)[0]?.textContent || undefined;

  return {
    author: getTag("dc:creator") || "Unknown",
    createdDate: getTag("dcterms:created"),
    modifiedDate: getTag("dcterms:modified"),
  };
};
