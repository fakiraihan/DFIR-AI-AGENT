import { createStyledReportDocxBlob } from './docxReportFormatter';

const PDF_MARGIN_MM = [10, 8, 10, 8];
const A4_WIDTH_MM = 210;
const CSS_PIXELS_PER_MM = 96 / 25.4;
const PDF_PRINTABLE_WIDTH_PX = Math.floor(
  (A4_WIDTH_MM - PDF_MARGIN_MM[1] - PDF_MARGIN_MM[3]) * CSS_PIXELS_PER_MM
);

export const PDF_EXPORT_WIDTH_PX = PDF_PRINTABLE_WIDTH_PX;

const PDF_PRINT_CSS = `
  @page {
    size: A4 portrait;
    margin: ${PDF_MARGIN_MM[0]}mm ${PDF_MARGIN_MM[1]}mm ${PDF_MARGIN_MM[2]}mm ${PDF_MARGIN_MM[3]}mm;
  }

  html,
  body {
    margin: 0 !important;
    padding: 0 !important;
    background: #ffffff !important;
    color: #172033 !important;
  }

  body {
    width: 100% !important;
    min-height: 100% !important;
    overflow: visible !important;
  }

  *,
  *::before,
  *::after {
    -webkit-print-color-adjust: exact !important;
    print-color-adjust: exact !important;
    box-sizing: border-box;
  }

  html::before,
  html::after,
  body::before,
  body::after {
    content: none !important;
    display: none !important;
    background: none !important;
  }

  .pdf-print-root {
    width: 100% !important;
    max-width: 100% !important;
    margin: 0 !important;
    padding: 0 !important;
    background: #ffffff !important;
    border: 0 !important;
    box-shadow: none !important;
    overflow: visible !important;
  }

  .pdf-print-root > * {
    width: 100% !important;
    max-width: 100% !important;
    background-color: #ffffff;
    border: 0 !important;
    box-shadow: none !important;
    overflow: visible !important;
  }

  h1,
  h2,
  h3,
  h4 {
    break-after: avoid;
    page-break-after: avoid;
  }

  table {
    width: 100%;
    break-inside: auto;
    page-break-inside: auto;
  }

  thead {
    display: table-header-group;
  }

  tfoot {
    display: table-footer-group;
  }

  tr,
  th,
  td,
  li,
  blockquote {
    break-inside: avoid;
    page-break-inside: avoid;
  }

  pre,
  code {
    white-space: pre-wrap;
  }
`;

const escapeHtml = (value) => (
  String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
);

const waitForCurrentLayout = async () => {
  if (document.fonts?.ready) {
    await document.fonts.ready.catch(() => {});
  }

  await new Promise((resolve) => {
    requestAnimationFrame(() => requestAnimationFrame(resolve));
  });
};

const buildPrintableReportHtml = async (element, fileName, extraCss = '') => {
  if (!element) {
    throw new Error('Report export element is not available');
  }

  await waitForCurrentLayout();

  const clone = element.cloneNode(true);
  clone.style.position = 'static';
  clone.style.inset = 'auto';
  clone.style.width = '100%';
  clone.style.maxWidth = '100%';
  clone.style.opacity = '1';
  clone.style.pointerEvents = 'auto';
  clone.style.overflow = 'visible';

  return `<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>${escapeHtml(fileName)}</title>
    <style>${PDF_PRINT_CSS}</style>
    ${extraCss ? `<style>${extraCss}</style>` : ''}
  </head>
  <body>
    <main class="pdf-print-root">${clone.outerHTML}</main>
  </body>
</html>`;
};

const WORD_ACCEPT_TYPE = {
  description: 'Word Document',
  accept: { 'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['.docx'] }
};

const triggerBrowserDownload = async (blob, defaultFileName) => {
  const downloadUrl = window.URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = downloadUrl;
  link.download = defaultFileName;
  link.rel = 'noopener';
  link.style.display = 'none';
  document.body.appendChild(link);
  link.click();

  window.setTimeout(() => {
    if (link.parentNode) {
      link.parentNode.removeChild(link);
    }
    window.URL.revokeObjectURL(downloadUrl);
  }, 1000);
};

const prepareSaveFile = async (defaultFileName, acceptType) => {
  if (window.showSaveFilePicker) {
    try {
      const handle = await window.showSaveFilePicker({
        suggestedName: defaultFileName,
        types: [
          acceptType
        ],
      });

      return async (blob) => {
        const writable = await handle.createWritable();
        await writable.write(blob);
        await writable.close();
      };
    } catch (err) {
      if (err.name === 'AbortError') {
        return null;
      }

      console.warn('File System Access API failed, falling back to download link', err);
    }
  }

  return (blob) => triggerBrowserDownload(blob, defaultFileName);
};

/**
 * Shared save helper that uses File System Access API if available,
 * otherwise falls back to a standard anchor download.
 */
export const saveFile = async (blob, defaultFileName, acceptType) => {
  if (window.showSaveFilePicker) {
    try {
      const handle = await window.showSaveFilePicker({
        suggestedName: defaultFileName,
        types: [
          acceptType
        ],
      });
      const writable = await handle.createWritable();
      await writable.write(blob);
      await writable.close();
      return;
    } catch (err) {
      if (err.name !== 'AbortError') {
        console.warn('File System Access API failed, falling back to download link', err);
      } else {
        return; // User cancelled
      }
    }
  }

  // Fallback
  await triggerBrowserDownload(blob, defaultFileName);
};

export const exportToDocx = async (markdownText, fileName) => {
  try {
    const savePreparedFile = await prepareSaveFile(fileName, WORD_ACCEPT_TYPE);
    if (!savePreparedFile) return;

    const blob = await createStyledReportDocxBlob(markdownText, fileName);
    await savePreparedFile(blob);
  } catch (error) {
    console.error('Failed to export DOCX:', error);
    throw error;
  }
};

export const exportToPdf = async (element, fileName) => {
  try {
    const html = await buildPrintableReportHtml(element, fileName);
    const response = await fetch('/api/report-export/pdf', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ html, filename: fileName }),
    });

    if (!response.ok) {
      let message = `PDF export failed with status ${response.status}`;
      try {
        const errorPayload = await response.json();
        message = errorPayload?.detail || message;
      } catch (parseError) {
        // Keep the status-based message if the backend returned non-JSON.
      }
      throw new Error(message);
    }

    const pdfBlob = await response.blob();
    await saveFile(pdfBlob, fileName, {
      description: 'PDF Document',
      accept: { 'application/pdf': ['.pdf'] }
    });
  } catch (error) {
    console.error('Failed to export PDF:', error);
    throw error;
  }
};
