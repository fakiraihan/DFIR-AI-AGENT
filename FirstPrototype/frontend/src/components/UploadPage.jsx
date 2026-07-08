import React, { useState, useRef } from "react";
import axios from "axios";
import {
  Box,
  Typography,
  Paper,
  Button,
  Alert,
  CircularProgress,
  Chip,
  Stack,
  Grid,
  IconButton,
  Container,
} from "@mui/material";
import CloudUploadIcon from "@mui/icons-material/CloudUpload";
import InsertDriveFileIcon from "@mui/icons-material/InsertDriveFile";
import CloseIcon from "@mui/icons-material/Close";
import PlayArrowIcon from "@mui/icons-material/PlayArrow";
import AssessmentIcon from "@mui/icons-material/Assessment";
import AccountCircleRoundedIcon from "@mui/icons-material/AccountCircleRounded";

const UploadPage = ({ onUploadSuccess, currentUser }) => {
  const [file, setFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [analyzeResult, setAnalyzeResult] = useState(null);
  const [error, setError] = useState(null);
  const [dragActive, setDragActive] = useState(false);

  const fileInputRef = useRef(null);

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileSelect(e.dataTransfer.files[0]);
    }
  };

  const handleFileSelect = (selectedFile) => {
    const allowedExtensions = [".evtx", ".log", ".txt", ".csv"];
    const fileExt = selectedFile.name
      .substring(selectedFile.name.lastIndexOf("."))
      .toLowerCase();
    if (!allowedExtensions.includes(fileExt)) {
      setError(
        `File type not supported. Allowed: ${allowedExtensions.join(", ")}`,
      );
      return;
    }
    setFile(selectedFile);
    setAnalyzeResult(null);
    setError(null);
  };

  const handleFileInput = (e) => {
    if (e.target.files && e.target.files[0]) {
      handleFileSelect(e.target.files[0]);
    }
  };

  const handleUpload = async () => {
    if (!file) return;
    setUploading(true);
    setError(null);
    const formData = new FormData();
    formData.append("file", file);
    try {
      const uploadResponse = await axios.post("/api/upload", formData, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      const sessionId = uploadResponse.data.session_id;
      await axios.post(`/api/investigate/${sessionId}`);
      onUploadSuccess(sessionId);
    } catch (err) {
      setError(
        err.response?.data?.detail || "Upload failed. Please try again.",
      );
    } finally {
      setUploading(false);
    }
  };

  const handleQuickAnalyze = async () => {
    if (!file) return;
    setAnalyzing(true);
    setError(null);
    setAnalyzeResult(null);
    const formData = new FormData();
    formData.append("file", file);
    formData.append("max_lines", "20000");
    formData.append("sample_step", "1");
    formData.append("anomaly_limit", "40");
    try {
      const response = await axios.post("/api/analyze", formData, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      setAnalyzeResult(response.data);
    } catch (err) {
      setAnalyzeResult(null);
      setError(
        err.response?.data?.detail || "Quick analyze failed. Please try again.",
      );
    } finally {
      setAnalyzing(false);
    }
  };

  const formatFileSize = (bytes) => {
    if (bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + " " + sizes[i];
  };

  return (
    <Box sx={{ width: "100%", pb: 8 }}>
      {/* ── HERO / LANDING SECTION ── */}
      

      {/* ── UPLOAD SECTION ── */}
      <Container maxWidth="md" sx={{ pt: 6 }}>
            <Paper
              elevation={0}
              sx={{
                p: 5,
                mb: 4,
                border: "2px dashed",
                borderColor: dragActive
                  ? "primary.main"
                  : "rgba(147, 197, 253, 0.2)",
                bgcolor: dragActive
                  ? "rgba(37, 99, 235, 0.12)"
                  : "rgba(15, 23, 42, 0.84)",
                borderRadius: 2,
                textAlign: "center",
                cursor: "pointer",
                transition:
                  "background-color 0.2s ease, border-color 0.2s ease, box-shadow 0.2s ease",
                boxShadow: dragActive
                  ? "0 0 0 1px rgba(147, 197, 253, 0.28)"
                  : "none",
                "&:hover": {
                  borderColor: "primary.main",
                  bgcolor: "rgba(37, 99, 235, 0.08)",
                  boxShadow: "0 0 0 1px rgba(147, 197, 253, 0.22)",
                },
              }}
              onDragEnter={handleDrag}
              onDragLeave={handleDrag}
              onDragOver={handleDrag}
              onDrop={handleDrop}
              onClick={() => !file && fileInputRef.current?.click()}
            >
              <input
                ref={fileInputRef}
                type="file"
                onChange={handleFileInput}
                accept=".evtx,.log,.txt,.csv"
                style={{ display: "none" }}
              />

              {!file ? (
                <Box sx={{ py: 6 }}>
                  <CloudUploadIcon
                    sx={{
                      fontSize: 80,
                      color: "primary.main",
                      mb: 3,
                      filter: "none",
                    }}
                  />
                  <Typography
                    variant="h5"
                    gutterBottom
                    sx={{ fontWeight: 600, color: "#F8FAFC" }}
                  >
                    Drop your log file here
                  </Typography>
                  <Typography variant="body1" color="text.secondary">
                    or click to browse from your computer
                  </Typography>
                </Box>
              ) : (
                <Box
                  sx={{
                    display: "flex",
                    alignItems: "center",
                    p: 4,
                    bgcolor: "rgba(255,255,255,0.03)",
                    borderRadius: 3,
                    border: "1px solid rgba(255,255,255,0.05)",
                  }}
                >
                  <InsertDriveFileIcon
                    sx={{ fontSize: 56, color: "primary.main", mr: 3 }}
                  />
                  <Box sx={{ flexGrow: 1, textAlign: "left" }}>
                    <Typography
                      variant="h5"
                      noWrap
                      sx={{ fontWeight: 600, color: "#F8FAFC", mb: 0.5 }}
                    >
                      {file.name}
                    </Typography>
                    <Typography variant="body1" color="text.secondary">
                      {formatFileSize(file.size)}
                    </Typography>
                  </Box>
                  <IconButton
                    color="error"
                    onClick={(e) => {
                      e.stopPropagation();
                      setFile(null);
                      setAnalyzeResult(null);
                      setError(null);
                    }}
                    sx={{
                      bgcolor: "rgba(244, 63, 94, 0.1)",
                      "&:hover": { bgcolor: "rgba(244, 63, 94, 0.2)" },
                      p: 1.5,
                    }}
                  >
                    <CloseIcon />
                  </IconButton>
                </Box>
              )}
            </Paper>

            {error && (
              <Alert severity="error" sx={{ mb: 4 }}>
                {error}
              </Alert>
            )}

            <Alert
              severity="success"
              icon={<AccountCircleRoundedIcon />}
              sx={{
                mb: 3,
                bgcolor: "rgba(16, 185, 129, 0.12)",
                color: "#BBF7D0",
                border: "1px solid",
                borderColor: "rgba(16, 185, 129, 0.26)",
              }}
            >
              {`Signed in as ${currentUser?.name || currentUser?.username || "Analyst"}. New investigations will be saved to this profile.`}
            </Alert>

            <Stack direction={{ xs: "column", sm: "row" }} spacing={2}>
              <Button
                variant="contained"
                color="primary"
                size="large"
                fullWidth
                startIcon={
                  uploading ? (
                    <CircularProgress size={24} color="inherit" />
                  ) : (
                    <PlayArrowIcon />
                  )
                }
                onClick={handleUpload}
                disabled={!file || uploading || analyzing}
                sx={{ py: 2, fontSize: "1.1rem" }}
              >
                {uploading
                  ? "Starting Investigation..."
                  : "Start Full Investigation"}
              </Button>
              <Button
                variant="outlined"
                color="primary"
                size="large"
                fullWidth
                startIcon={
                  analyzing ? (
                    <CircularProgress size={24} color="inherit" />
                  ) : (
                    <AssessmentIcon />
                  )
                }
                onClick={handleQuickAnalyze}
                disabled={!file || analyzing || uploading}
                sx={{
                  py: 2,
                  fontSize: "1.1rem",
                  bgcolor: "rgba(15, 23, 42, 0.5)",
                }}
              >
                {analyzing ? "Running Analysis..." : "Run Quick Analysis"}
              </Button>
            </Stack>

            {analyzeResult && (
              <Paper
                elevation={0}
                sx={{
                  p: 4,
                  mt: 5,
                  borderRadius: 2,
                  bgcolor: "rgba(15, 23, 42, 0.84)",
                  border: "1px solid rgba(148, 163, 184, 0.16)",
                }}
              >
                <Box
                  sx={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    mb: 4,
                  }}
                >
                  <Typography
                    variant="h5"
                    sx={{ color: "#F8FAFC", fontWeight: 600 }}
                  >
                    Phase 1 Debug Result
                  </Typography>
                  <Chip
                    label="/api/analyze"
                    size="small"
                    sx={{
                      bgcolor: "rgba(37,99,235,0.12)",
                      color: "#bfdbfe",
                      borderColor: "rgba(147,197,253,0.26)",
                    }}
                    variant="outlined"
                  />
                </Box>

                <Grid container spacing={2} sx={{ mb: 4 }}>
                  {[
                    {
                      label: "Parsed Lines",
                      value: analyzeResult.summary?.parsed_lines,
                    },
                    {
                      label: "Templates",
                      value: analyzeResult.summary?.template_count,
                    },
                    {
                      label: "Windows",
                      value: analyzeResult.summary?.window_count,
                    },
                    {
                      label: "Anomalies",
                      value: analyzeResult.summary?.anomaly_count,
                    },
                    {
                      label: "Strict Anomalies",
                      value: analyzeResult.summary?.strict_anomaly_count,
                    },
                    {
                      label: "Skipped Windows",
                      value: analyzeResult.summary?.skipped_windows,
                    },
                    {
                      label: "Avg Unknown Ratio",
                      value: Number(
                        analyzeResult.summary?.avg_unknown_ratio ?? 0,
                      ).toFixed(2),
                    },
                  ].map((stat, idx) => (
                    <Grid item xs={6} sm={4} key={idx}>
                      <Box
                        sx={{
                          p: 2.5,
                          bgcolor: "rgba(255,255,255,0.02)",
                          borderRadius: 3,
                          border: "1px solid rgba(255,255,255,0.05)",
                        }}
                      >
                        <Typography
                          variant="caption"
                          color="text.secondary"
                          display="block"
                          sx={{
                            mb: 1,
                            fontSize: "0.8rem",
                            textTransform: "uppercase",
                            letterSpacing: 0,
                          }}
                        >
                          {stat.label}
                        </Typography>
                        <Typography
                          variant="h5"
                          sx={{
                            fontWeight: 600,
                            color: "#F8FAFC",
                            lineHeight: 1,
                          }}
                        >
                          {stat.value ?? 0}
                        </Typography>
                      </Box>
                    </Grid>
                  ))}
                </Grid>

                {(analyzeResult.summary?.avg_unknown_ratio ?? 0) >=
                  (analyzeResult.debug?.max_unknown_ratio ?? 0.4) && (
                  <Alert severity="warning" sx={{ mb: 3 }}>
                    High unknown template ratio detected. Parser-template
                    mismatch may inflate anomalies.
                  </Alert>
                )}
                {analyzeResult.debug?.result_truncated && (
                  <Alert severity="info" sx={{ mb: 4 }}>
                    Result truncated for faster debugging. Increase
                    anomaly_limit if needed.
                  </Alert>
                )}

                <Box sx={{ mt: 2 }}>
                  {(analyzeResult.anomaly_results || [])
                    .slice(0, 8)
                    .map((window) => (
                      <Box
                        key={window.window_id}
                        sx={{
                          mb: 3,
                          p: 3,
                          border: "1px solid rgba(255,255,255,0.1)",
                          bgcolor: "rgba(0,0,0,0.2)",
                          borderRadius: 3,
                        }}
                      >
                        <Box
                          sx={{
                            display: "flex",
                            justifyContent: "space-between",
                            mb: 2,
                          }}
                        >
                          <Typography
                            variant="subtitle1"
                            sx={{ fontWeight: 600, color: "#F8FAFC" }}
                          >
                            Window #{window.window_id}
                          </Typography>
                          <Chip
                            label={`score ${Number(window.anomaly_score || 0).toFixed(3)}`}
                            size="small"
                            color="warning"
                            variant="outlined"
                          />
                        </Box>
                        <Typography
                          variant="body2"
                          color="text.secondary"
                          display="block"
                          sx={{
                            mb: 2.5,
                            fontFamily: "monospace",
                            bgcolor: "rgba(255,255,255,0.03)",
                            p: 1.5,
                            borderRadius: 2,
                          }}
                        >
                          actual: {window.actual_event || "-"} | predicted:{" "}
                          {window.predicted_event || "-"}
                        </Typography>
                        <Stack spacing={1.5}>
                          {(window.lines || []).map((line) => (
                            <Box
                              key={`${window.window_id}-${line.line_number}`}
                              sx={{
                                p: 1.5,
                                display: "flex",
                                alignItems: "flex-start",
                                bgcolor: line.is_anomalous_line
                                  ? "rgba(244, 63, 94, 0.08)"
                                  : "transparent",
                                borderRadius: 2,
                                border: line.is_anomalous_line
                                  ? "1px solid rgba(244, 63, 94, 0.28)"
                                  : "1px solid transparent",
                              }}
                            >
                              <Typography
                                variant="caption"
                                sx={{
                                  minWidth: 40,
                                  color: "text.secondary",
                                  fontFamily: "monospace",
                                  pt: 0.5,
                                }}
                              >
                                L{line.line_number}
                              </Typography>
                              <Typography
                                variant="body2"
                                sx={{
                                  flexGrow: 1,
                                  fontFamily: "monospace",
                                  wordBreak: "break-all",
                                  color: line.is_anomalous_line
                                    ? "#fecdd3"
                                    : "#CBD5E1",
                                }}
                              >
                                {line.event_template}
                              </Typography>
                              {line.is_anomalous_line && (
                                <Chip
                                  label="anomalous"
                                  size="small"
                                  color="error"
                                  sx={{
                                    height: 20,
                                    ml: 1,
                                    fontSize: "0.65rem",
                                  }}
                                />
                              )}
                            </Box>
                          ))}
                        </Stack>
                      </Box>
                    ))}
                </Box>
              </Paper>
            )}
      </Container>
    </Box>
  );
};

export default UploadPage;
