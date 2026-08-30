import { EmailAnalysisInput } from './types';

export function parseEmlFileContent(fileContent: string): EmailAnalysisInput {
  // Normalize line endings
  const normalized = fileContent.replace(/\r\n/g, '\n');
  
  // RFC 5322 header and body are separated by two consecutive newlines
  const separatorIndex = normalized.indexOf('\n\n');
  
  if (separatorIndex === -1) {
    // If no header/body separator found, treat entire content as headers or body
    return {
      raw_headers: fileContent,
      email_body: '',
      metadata: {
        file_source: 'Uploaded .EML file',
        parsed_at: new Date().toISOString()
      }
    };
  }

  const rawHeaders = normalized.substring(0, separatorIndex).trim();
  let emailBody = normalized.substring(separatorIndex + 2).trim();

  // If body is multipart, extract readable plaintext or html
  const contentTypeMatch = rawHeaders.match(/Content-Type:\s*([^\r\n;]+)(?:;\s*boundary="?([^"\r\n]+)"?)?/i);
  if (contentTypeMatch && contentTypeMatch[2]) {
    const boundary = contentTypeMatch[2];
    const parts = emailBody.split(`--${boundary}`);
    for (const part of parts) {
      if (part.includes('Content-Type: text/plain') || part.includes('Content-Type: text/html')) {
        const partSeparator = part.indexOf('\n\n');
        if (partSeparator !== -1) {
          emailBody = part.substring(partSeparator + 2).trim();
          break;
        }
      }
    }
  }

  return {
    raw_headers: rawHeaders,
    email_body: emailBody,
    metadata: {
      file_source: 'Uploaded .EML file',
      parsed_at: new Date().toISOString()
    }
  };
}

