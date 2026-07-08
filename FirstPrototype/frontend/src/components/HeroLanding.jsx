import React from "react";
import {
  Box,
  Typography,
  Button,
  Container,
  Stack,
  Grid,
} from "@mui/material";
import RadarIcon from "@mui/icons-material/Radar";
import SecurityIcon from "@mui/icons-material/Security";
import CloudUploadIcon from "@mui/icons-material/CloudUpload";
import InsertDriveFileIcon from "@mui/icons-material/InsertDriveFile";
import StorageIcon from "@mui/icons-material/Storage";
import AccountTreeIcon from "@mui/icons-material/AccountTree";
import CodeIcon from "@mui/icons-material/Code";
import ShieldIcon from "@mui/icons-material/Shield";
import LanguageIcon from "@mui/icons-material/Language";
import PsychologyIcon from "@mui/icons-material/Psychology";
import MemoryIcon from "@mui/icons-material/Memory";
import KeyboardArrowDownIcon from "@mui/icons-material/KeyboardArrowDown";
import AssessmentIcon from "@mui/icons-material/Assessment";
import SpeedIcon from "@mui/icons-material/Speed";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import ApiIcon from "@mui/icons-material/Api";
import GpsFixedIcon from "@mui/icons-material/GpsFixed";
import FilterListIcon from "@mui/icons-material/FilterList";
import jejakAgentLogo from "../../jejakAgentv3.png";

const SURFACE = "rgba(15,23,42,0.82)";
const SURFACE_HOVER = "rgba(15,23,42,0.94)";
const BORDER = "rgba(148,163,184,0.16)";
const ACCENT = "#8fbffa";
const ACTION = "#2563eb";
const ACTION_HOVER = "#1d4ed8";
const BODY = "#cbd5e1";
const MUTED = "#94a3b8";

// ─── Animated section wrapper ─────────────────────────────────────────────────
const AnimSection = ({ children, sx = {} }) => <Box sx={sx}>{children}</Box>;

// ─── Section heading ──────────────────────────────────────────────────────────
const SectionLabel = ({ overline, title, subtitle }) => (
  <Box sx={{ textAlign: "left", mb: 4.5, maxWidth: 760 }}>
    <Typography
      variant="body2"
      sx={{
        color: ACCENT,
        fontWeight: 700,
        fontSize: "0.9rem",
        mb: 0.75,
      }}
    >
      {overline}
    </Typography>
    <Typography
      variant="h4"
      component="h2"
      sx={{
        fontWeight: 800,
        color: "#F8FAFC",
        mt: 0.5,
        mb: 1.2,
        letterSpacing: 0,
        lineHeight: 1.2,
      }}
    >
      {title}
    </Typography>
    {subtitle && (
      <Typography
        variant="body1"
        sx={{ color: BODY, maxWidth: 680, lineHeight: 1.65 }}
      >
        {subtitle}
      </Typography>
    )}
  </Box>
);

// ─── Data ─────────────────────────────────────────────────────────────────────
const TECH_STACK = [
  {
    category: "Frontend",
    color: "#93c5fd",
    icon: <CodeIcon sx={{ fontSize: 20 }} />,
    items: [
      { name: "React 18", desc: "UI Library" },
      { name: "Vite 5", desc: "Build Tool" },
      { name: "Material UI v5", desc: "Component System" },
      { name: "Axios", desc: "HTTP Client" }    
    ],
  },
  {
    category: "Backend",
    color: "#8aa4c4",
    icon: <StorageIcon sx={{ fontSize: 20 }} />,
    items: [
      { name: "FastAPI", desc: "Web Framework" },
      { name: "LangGraph", desc: "Agent Orchestration" },
      { name: "Python 3.10+", desc: "Runtime" },
      { name: "Uvicorn", desc: "ASGI Server" },
      { name: "Pydantic v2", desc: "Data Validation" },
    ],
  },
  {
    category: "Models",
    color: "#a9a4c7",
    icon: <PsychologyIcon sx={{ fontSize: 20 }} />,
    items: [
      { name: "Foundation-Sec-8B", desc: "Cybersecurity model" },
      { name: "DeepLog (LSTM)", desc: "Anomaly Detector" },
      { name: "Drain", desc: "Log Parser" },
      { name: "Ollama", desc: "Local Inference" },
      { name: "LangChain Tools", desc: "Tool Use" },
    ],
  },
  {
    category: "Threat Intelligence",
    color: "#d6b36a",
    icon: <ShieldIcon sx={{ fontSize: 20 }} />,
    items: [
      { name: "VirusTotal", desc: "Hash & URL Intel" },
      { name: "OTX AlienVault", desc: "Threat Feeds" },
      { name: "ThreatFox", desc: "IoC Database" },
      { name: "GreyNoise", desc: "Internet Noise" },
      { name: "URLHaus", desc: "Malicious URLs" },
      { name: "MalwareBazaar", desc: "Malware Hashes" },
    ],
  },
];

const PIPELINE_STEPS = [
  {
    num: "01",
    name: "Upload & Session",
    icon: <CloudUploadIcon />,
    color: "#93c5fd",
    desc: "Upload EVTX, CSV, LOG, or TXT files. An isolated session is created per investigation to keep artifacts separate.",
  },
  {
    num: "02",
    name: "Log Parsing: Drain",
    icon: <RadarIcon />,
    color: "#8aa4c4",
    desc: "Drain algorithm online-parses raw log lines into structured templates, normalizing dynamic variables (IPs, hashes, timestamps) for ML input.",
  },
  {
    num: "03",
    name: "DeepLog Detection",
    icon: <MemoryIcon />,
    color: "#d58b9a",
    desc: "LSTM deep learning model scores log sequences for next-event anomalies. Validated at F1 0.9489, Recall 0.9151, FPR only 1.23%.",
  },
  {
    num: "04",
    name: "LLM Anomaly Gate",
    icon: <FilterListIcon />,
    color: "#93c5fd",
    desc: "Foundation-Sec-8B batch-reviews candidate anomalies for semantic plausibility, reducing false positives before deep analysis.",
  },
  {
    num: "05",
    name: "JejakAgent: LangGraph",
    icon: <AccountTreeIcon />,
    color: "#a9a4c7",
    desc: "Stateful LangGraph agent reasons over filtered anomalies, selects investigation tools, and iteratively builds the threat narrative.",
  },
  {
    num: "06",
    name: "Threat Intelligence",
    icon: <LanguageIcon />,
    color: "#d6b36a",
    desc: "6 integrated APIs enrich extracted IoCs in real time: IPs, domains, file hashes, and URLs checked against live threat feeds.",
  },
  {
    num: "07",
    name: "Report Generation",
    icon: <InsertDriveFileIcon />,
    color: "#93c5fd",
    desc: "Structured Markdown/PDF incident report with event timeline, enriched IoCs, MITRE ATT&CK tactic mapping, and recommended mitigations.",
  },
];

const STATS = [
  {
    value: "0.9489",
    label: "DeepLog F1 Score",
    sub: "LSTM anomaly detection performance",
    color: "#93c5fd",
    icon: <SpeedIcon sx={{ fontSize: 28 }} />,
  },
  {
    value: "0.9151",
    label: "Recall Rate",
    sub: "True positive anomaly coverage",
    color: "#bfdbfe",
    icon: <GpsFixedIcon sx={{ fontSize: 28 }} />,
  },
  {
    value: "6",
    label: "Threat Intel APIs",
    sub: "Real-time IoC enrichment sources",
    color: "#d6b36a",
    icon: <ApiIcon sx={{ fontSize: 28 }} />,
  },
  {
    value: "9",
    label: "MITRE ATT&CK",
    sub: "Tactics covered in evaluation",
    color: "#a9a4c7",
    icon: <AssessmentIcon sx={{ fontSize: 28 }} />,
  },
];

const FORMAT_CHIPS = [
  { label: "EVTX", color: "#8aa4c4" },
  { label: "CSV", color: "#93c5fd" },
  { label: "LOG", color: "#d58b9a" },
  { label: "TXT", color: "#a9a4c7" },
];

// Section divider
const SignalDivider = () => (
  <Box
    sx={{
      width: "100%",
      height: "1px",
      bgcolor: BORDER,
      my: 0,
    }}
  />
);

// Main component
const HeroLanding = ({ onStart }) => {
  return (
    <Box sx={{ width: "100%", maxWidth: "100%", overflowX: "hidden" }}>
      {/* SECTION 1: HERO */}
      <Box
        sx={{
          minHeight: "94vh",
          display: "flex",
          flexDirection: "column",
          justifyContent: "center",
          alignItems: "center",
          textAlign: "center",
          position: "relative",
          overflow: "hidden",
        }}
      >
        <Box
          sx={{
            position: "absolute",
            inset: 0,
            backgroundImage: `
              linear-gradient(rgba(148, 163, 184, 0.032) 1px, transparent 1px),
              linear-gradient(90deg, rgba(148, 163, 184, 0.028) 1px, transparent 1px),
              linear-gradient(180deg, rgba(7, 11, 20, 0) 0%, #070b14 92%)
            `,
            backgroundSize: "56px 56px, 56px 56px, 100% 100%",
            maskImage:
              "linear-gradient(180deg, rgba(0,0,0,0.88), rgba(0,0,0,0.32) 78%, transparent)",
            zIndex: 0,
            pointerEvents: "none",
          }}
        />

        <Container
          maxWidth="lg"
          sx={{ position: "relative", zIndex: 1, py: { xs: 7, md: 9 } }}
        >
          <Stack spacing={3.2} alignItems="center" sx={{ maxWidth: 900, mx: "auto" }}>
            {/* Brand lockup */}
            <Box
              sx={{
                display: "inline-flex",
                alignItems: "center",
                justifyContent: "center",
                px: { xs: 1.4, sm: 2 },
                py: { xs: 0.8, sm: 1 },
                borderRadius: 3,
                bgcolor: "rgba(15,23,42,0.72)",
                border: "1px solid rgba(147,197,253,0.22)",
                boxShadow: "0 18px 60px rgba(2, 6, 23, 0.26)",
              }}
            >
              <Box
                component="img"
                src={jejakAgentLogo}
                alt="JejakAgent"
                sx={{
                  width: { xs: 218, sm: 280 },
                  height: { xs: 52, sm: 64 },
                  objectFit: "contain",
                }}
              />
            </Box>

            {/* Main heading */}
            <Typography
              variant="h2"
              component="h1"
              sx={{
                fontWeight: 900,
                color: "#F8FAFC",
                letterSpacing: 0,
                lineHeight: 1.08,
                fontSize: { xs: "2.25rem", sm: "3rem", md: "3.7rem" },
                maxWidth: 840,
                textWrap: "balance",
              }}
            >
              Trace Every Log,
              <Box component="span" sx={{ display: "block", color: ACCENT }}>
                Trust Every Finding.
              </Box>
            </Typography>

            {/* Tagline */}
            <Typography
              variant="h6"
              sx={{
                maxWidth: 660,
                mx: "auto",
                color: BODY,
                fontWeight: 400,
                lineHeight: 1.7,
                fontSize: { xs: "0.95rem", sm: "1.03rem" },
                letterSpacing: 0,
                textWrap: "pretty",
              }}
            >
              Our Agent turns raw log into evidence, IOC enrichment, timelines, and DFIR Reports, 
              so analysts can investigate faster without losing visibility or control.
            </Typography>

            {/* Format / tech chips */}
            <Stack
              direction="row"
              spacing={1.1}
              justifyContent="center"
              flexWrap="wrap"
              useFlexGap
              sx={{ maxWidth: 720 }}
            >
              {FORMAT_CHIPS.map((tag) => (
                <Box
                  key={tag.label}
                  sx={{
                    display: "flex",
                    alignItems: "center",
                    gap: 0.8,
                    px: 1.7,
                    py: 0.62,
                    borderRadius: "20px",
                    border: tag.highlight
                      ? "1px solid rgba(245,158,11,0.36)"
                      : "1px solid rgba(147,197,253,0.16)",
                    bgcolor: tag.highlight
                      ? "rgba(245,158,11,0.06)"
                      : "rgba(15,23,42,0.52)",
                    transition: "border-color 0.2s ease, background-color 0.2s ease",
                    cursor: "default",
                    "&:hover": {
                      borderColor: tag.color,
                      bgcolor: tag.highlight
                        ? "rgba(245,158,11,0.1)"
                        : "rgba(37,99,235,0.1)",
                    },
                  }}
                >
                  {tag.icon ? (
                    tag.icon
                  ) : (
                    <Box
                      sx={{
                        width: 5,
                        height: 5,
                        borderRadius: "50%",
                        bgcolor: tag.color,
                      }}
                    />
                  )}
                  <Typography
                    variant="body2"
                    sx={{
                      fontSize: "0.78rem",
                      fontWeight: 650,
                      color: tag.highlight ? "#d6b36a" : "#e2e8f0",
                      letterSpacing: 0,
                    }}
                  >
                    {tag.label}
                  </Typography>
                </Box>
              ))}
            </Stack>

            <Stack
              direction={{ xs: "column", sm: "row" }}
              spacing={1.4}
              justifyContent="center"
              sx={{ width: "100%", pt: 0.8 }}
            >
              <Button
                variant="contained"
                size="large"
                onClick={onStart}
                sx={{
                  alignSelf: { xs: "stretch", sm: "center" },
                  px: 3,
                  py: 1.25,
                  bgcolor: ACTION,
                  borderRadius: 999,
                  fontWeight: 800,
                  boxShadow: "0 0 0 1px rgba(147,197,253,0.2)",
                  "&:hover": {
                    bgcolor: ACTION_HOVER,
                    boxShadow: "0 0 0 1px rgba(147,197,253,0.34)",
                  },
                }}
              >
                Start investigation
              </Button>

            </Stack>

            {/* Scroll down indicator */}
            <Box
              sx={{
                display: "flex",
                flexDirection: "column",
                alignItems: "center",
                gap: 0.5,
                pt: 1.4,
              }}
            >
              <Typography
                variant="caption"
                sx={{
                  color: "#64748b",
                  letterSpacing: 0,
                  textTransform: "none",
                  fontSize: "0.65rem",
                }}
              >
                Scroll to explore
              </Typography>
              <KeyboardArrowDownIcon
                sx={{
                  color: ACCENT,
                  fontSize: 28,
                  opacity: 0.62,
                }}
              />
            </Box>
          </Stack>
        </Container>
      </Box>

      {/* SECTION 2: ARCHITECTURE */}
      <SignalDivider />
      <Box
        sx={{
          py: { xs: 8, md: 12 },
        }}
      >
        <Container maxWidth="lg">
          <AnimSection>
            <SectionLabel
              overline="Under the Hood"
              title="The Stack"
              subtitle="A purpose-built combination of modern web tech, local model inference, and live threat intelligence APIs."
            />
          </AnimSection>

          <Grid container spacing={1.5}>
            {TECH_STACK.map((cat, idx) => (
              <Grid item xs={12} sm={6} lg={3} key={cat.category}>
                <AnimSection delay={idx * 80}>
                  <Box
                    sx={{
                      p: 3,
                      height: "100%",
                      minHeight: 260,
                      bgcolor: SURFACE,
                      border: `1px solid ${BORDER}`,
                      borderRadius: 2,
                      transition:
                        "background-color 0.2s ease, border-color 0.2s ease",
                      "&:hover": {
                        bgcolor: SURFACE_HOVER,
                        borderColor: `${cat.color}4d`,
                      },
                    }}
                  >
                    {/* Category header */}
                    <Box
                      sx={{
                        display: "flex",
                        alignItems: "center",
                        gap: 1.2,
                        mb: 2.5,
                      }}
                    >
                      <Box
                        sx={{
                          p: 0.9,
                          bgcolor: "rgba(2,6,23,0.42)",
                          border: `1px solid ${cat.color}30`,
                          borderRadius: 1.5,
                          color: cat.color,
                          display: "flex",
                        }}
                      >
                        {cat.icon}
                      </Box>
                      <Typography
                        variant="subtitle2"
                        sx={{
                          fontWeight: 700,
                          color: "#E2E8F0",
                          fontSize: "0.88rem",
                        }}
                      >
                        {cat.category}
                      </Typography>
                    </Box>

                    {/* Items */}
                    <Stack spacing={1.4}>
                      {cat.items.map((item) => (
                        <Box
                          key={item.name}
                          sx={{
                            display: "flex",
                            alignItems: "center",
                            gap: 1.2,
                          }}
                        >
                          <Box
                            sx={{
                              width: 4,
                              height: 4,
                              borderRadius: "50%",
                              bgcolor: cat.color,
                              opacity: 0.55,
                              flexShrink: 0,
                            }}
                          />
                          <Typography
                            sx={{
                              fontWeight: 600,
                              color: "#CBD5E1",
                              fontSize: "0.84rem",
                              flexGrow: 1,
                            }}
                          >
                            {item.name}
                          </Typography>
                          <Typography
                            sx={{
                              color: MUTED,
                              fontSize: "0.72rem",
                              whiteSpace: "nowrap",
                            }}
                          >
                            {item.desc}
                          </Typography>
                        </Box>
                      ))}
                    </Stack>
                  </Box>
                </AnimSection>
              </Grid>
            ))}
          </Grid>
        </Container>
      </Box>

      {/* SECTION 3: INVESTIGATION PIPELINE */}
      <SignalDivider />
      <Box id="investigation-pipeline" sx={{ py: { xs: 8, md: 12 }, scrollMarginTop: 88 }}>
        <Container maxWidth="lg">
          <AnimSection>
            <SectionLabel
              overline="Investigation Pipeline"
              title="How It Works"
              subtitle="Seven automated stages transform a raw log file into a comprehensive, analyst-ready threat report."
            />
          </AnimSection>

          <Grid container spacing={2}>
            {PIPELINE_STEPS.map((step, idx) => (
              <Grid item xs={12} sm={6} md={4} key={step.num}>
                <AnimSection delay={idx * 60}>
                  <Box
                    sx={{
                      p: 3,
                      height: "100%",
                      bgcolor: SURFACE,
                      border: `1px solid ${BORDER}`,
                      borderRadius: 2,
                      boxShadow: "none",
                      transition:
                        "border-color 0.2s ease, background-color 0.2s ease",
                      "&:hover": {
                        bgcolor: SURFACE_HOVER,
                        borderColor: `${step.color}66`,
                        boxShadow: "none",
                      },
                    }}
                  >
                    {/* Step number + icon */}
                    <Box
                      sx={{
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "space-between",
                        mb: 2,
                      }}
                    >
                      <Typography
                        sx={{
                          fontSize: "2.4rem",
                          fontWeight: 900,
                          lineHeight: 1,
                          color: "rgba(148, 163, 184, 0.32)",
                          fontFamily: '"Cascadia Mono", "Consolas", monospace',
                          letterSpacing: 0,
                        }}
                      >
                        {step.num}
                      </Typography>
                      <Box
                        sx={{
                          p: 1,
                          bgcolor: "rgba(2,6,23,0.42)",
                          borderRadius: 2,
                          color: step.color,
                          border: `1px solid ${step.color}3d`,
                          display: "flex",
                          alignItems: "center",
                        }}
                      >
                        {step.icon}
                      </Box>
                    </Box>

                    {/* Stage name */}
                    <Typography
                      variant="subtitle1"
                      sx={{
                        fontWeight: 700,
                        color: "#F8FAFC",
                        mb: 1,
                        lineHeight: 1.3,
                      }}
                    >
                      {step.name}
                    </Typography>

                    {/* Description */}
                    <Typography
                      variant="body2"
                      sx={{
                        color: BODY,
                        lineHeight: 1.65,
                        fontSize: "0.82rem",
                      }}
                    >
                      {step.desc}
                    </Typography>
                  </Box>
                </AnimSection>
              </Grid>
            ))}
          </Grid>
        </Container>
      </Box>

      {/* SECTION 5: WHAT YOU GET */}
      <SignalDivider />
      <Box sx={{ py: { xs: 8, md: 10 } }}>
        <Container maxWidth="md">
          <AnimSection>
            <SectionLabel
              overline="Output"
              title="What You Get"
              subtitle="Every investigation produces a structured, ready-to-share incident report."
            />
          </AnimSection>

          <AnimSection delay={100}>
            <Grid container spacing={2}>
              {[
                {
                  icon: <CheckCircleIcon sx={{ fontSize: 20 }} />,
                  color: "#93c5fd",
                  title: "Event Timeline",
                  desc: "Chronological sequence of suspicious events extracted from your logs.",
                },
                {
                  icon: <GpsFixedIcon sx={{ fontSize: 20 }} />,
                  color: ACCENT,
                  title: "Enriched IoCs",
                  desc: "IPs, domains, hashes, and URLs cross-referenced against 6 threat intel APIs.",
                },
                {
                  icon: <AssessmentIcon sx={{ fontSize: 20 }} />,
                  color: "#a9a4c7",
                  title: "MITRE ATT&CK Map",
                  desc: "Each anomaly annotated with relevant ATT&CK tactic and technique IDs.",
                },
                {
                  icon: <SecurityIcon sx={{ fontSize: 20 }} />,
                  color: "#d6b36a",
                  title: "Mitigations",
                  desc: "Response recommendations derived from the investigation evidence.",
                },
              ].map((item, idx) => (
                <Grid item xs={12} sm={6} key={item.title}>
                  <Box
                    sx={{
                      display: "flex",
                      gap: 2,
                      p: 2.5,
                      bgcolor: SURFACE,
                      border: `1px solid ${BORDER}`,
                      borderRadius: 2,
                      transition:
                        "border-color 0.2s ease, background-color 0.2s ease",
                      "&:hover": {
                        borderColor: `${item.color}40`,
                        bgcolor: SURFACE_HOVER,
                      },
                    }}
                  >
                    <Box
                      sx={{
                        p: 1,
                        bgcolor: `${item.color}18`,
                        borderRadius: 1.5,
                        color: item.color,
                        display: "flex",
                        alignItems: "flex-start",
                        flexShrink: 0,
                        height: "fit-content",
                        mt: 0.2,
                      }}
                    >
                      {item.icon}
                    </Box>
                    <Box>
                      <Typography
                        variant="subtitle2"
                        sx={{ fontWeight: 700, color: "#F8FAFC", mb: 0.5 }}
                      >
                        {item.title}
                      </Typography>
                      <Typography
                        variant="body2"
                        sx={{
                          color: BODY,
                          fontSize: "0.82rem",
                          lineHeight: 1.55,
                        }}
                      >
                        {item.desc}
                      </Typography>
                    </Box>
                  </Box>
                </Grid>
              ))}
            </Grid>
          </AnimSection>
        </Container>
      </Box>

      {/* SECTION 6: FINAL CTA */}
      <SignalDivider />
      <Box
        sx={{
          py: { xs: 10, md: 16 },
          textAlign: "center",
          position: "relative",
          overflow: "hidden",
          bgcolor: "rgba(7, 11, 20, 0.72)",
        }}
      >
        <Container maxWidth="sm">
          <AnimSection>
            <Typography
              variant="body2"
              sx={{
                color: ACCENT,
                fontWeight: 700,
                letterSpacing: 0,
                fontSize: "0.82rem",
              }}
            >
              Start a Case
            </Typography>
            <Typography
              variant="h3"
              sx={{
                fontWeight: 900,
                color: "#F8FAFC",
                mt: 0.5,
                mb: 2,
                letterSpacing: 0,
                lineHeight: 1.15,
                fontSize: { xs: "2rem", md: "2.8rem" },
              }}
            >
              Upload evidence.
              <br />
              <Box
                component="span"
                sx={{
                  color: "#d9e7e4",
                }}
              >
                Keep the trail visible.
              </Box>
            </Typography>
            <Typography
              variant="body1"
              sx={{ color: BODY, mb: 5, lineHeight: 1.65 }}
            >
              Drop a log file and let the DFIR pipeline preserve the path from
              raw event to anomaly, IOC, timeline, and report.
            </Typography>

            <Button
              variant="contained"
              size="large"
              endIcon={<SecurityIcon />}
              onClick={onStart}
              sx={{
                py: 1.8,
                px: 6,
                fontSize: "1.05rem",
                fontWeight: 700,
                borderRadius: 2,
                bgcolor: ACTION,
                boxShadow: "none",
                letterSpacing: 0,
                transition:
                  "background-color 0.2s ease, border-color 0.2s ease, transform 0.2s ease",
                "&:hover": {
                  transform: "translateY(-1px)",
                  bgcolor: ACTION_HOVER,
                  boxShadow: "none",
                },
                "&:active": { transform: "translateY(1px)" },
              }}
            >
              Start Investigation
            </Button>

            {/* Micro pipeline hint */}
            <Box
              sx={{
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                gap: 0.6,
                mt: 3,
                flexWrap: "wrap",
              }}
            >
              {[
                "Try JejakAgent Now!",
              ].map((step, idx, arr) => (
                <React.Fragment key={step}>
                  <Typography
                    variant="caption"
                    sx={{
                      color: MUTED,
                      fontSize: "0.7rem",
                      letterSpacing: 0,
                    }}
                  >
                    {step}
                  </Typography>
                  {idx < arr.length - 1 && (
                    <Typography variant="caption" sx={{ color: MUTED }}>
                      /
                    </Typography>
                  )}
                </React.Fragment>
              ))}
            </Box>
          </AnimSection>
        </Container>
      </Box>

      {/* ── FLOATING FAB ──────────────────────────────────────────────────── */}
    </Box>
  );
};

export default HeroLanding;
