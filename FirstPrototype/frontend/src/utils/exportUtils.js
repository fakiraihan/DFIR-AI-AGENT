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
  const downloadUrl = window.URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = downloadUrl;
  link.download = defaultFileName;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  window.URL.revokeObjectURL(downloadUrl);
};

export const exportToDocx = async (markdownText, fileName) => {
  try {
    const { convertMarkdownToDocx } = await import('@mohtasham/md-to-docx');
    const blob = await convertMarkdownToDocx(markdownText);
    await saveFile(blob, fileName, {
      description: 'Word Document',
      accept: { 'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['.docx'] }
    });
  } catch (error) {
    console.error('Failed to export DOCX:', error);
    throw error;
  }
};

export const exportToPdf = async (element, fileName) => {
  try {
    const html2pdfModule = await import('html2pdf.js');
    const html2pdf = html2pdfModule.default || html2pdfModule;
    const opt = {
      margin: [15, 15, 15, 15],
      filename: fileName,
      image: { type: 'jpeg', quality: 0.98 },
      html2canvas: { scale: 2, useCORS: true, letterRendering: true },
      jsPDF: { unit: 'mm', format: 'a4', orientation: 'portrait' }
    };
    
    // html2pdf().output('blob') generates a Promise resolving to a Blob
    const pdfBlob = await html2pdf().set(opt).from(element).output('blob');
    await saveFile(pdfBlob, fileName, {
      description: 'PDF Document',
      accept: { 'application/pdf': ['.pdf'] }
    });
  } catch (error) {
    console.error('Failed to export PDF:', error);
    throw error;
  }
};
