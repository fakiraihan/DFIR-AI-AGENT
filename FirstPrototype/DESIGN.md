---
name: JejakAgent
description: Professional futuristic DFIR workspace for evidence-bound cyber incident investigation.
colors:
  primary-blue: "#2563eb"
  primary-blue-light: "#bfdbfe"
  primary-blue-dark: "#1d4ed8"
  secondary-indigo: "#818cf8"
  secondary-indigo-dark: "#6366f1"
  info-blue: "#3b82f6"
  success-emerald: "#10b981"
  success-emerald-light: "#34d399"
  warning-amber: "#f59e0b"
  danger-rose: "#f43f5e"
  background-abyss: "#070b14"
  surface-slate: "#0f172a"
  surface-sidebar: "#0b0f19"
  ink-primary: "#f8fafc"
  ink-secondary: "#cbd5e1"
  ink-muted: "#94a3b8"
  ink-subtle: "#64748b"
  border-slate: "#94a3b8"
  white: "#ffffff"
typography:
  display:
    fontFamily: "Segoe UI Variable, Aptos, -apple-system, BlinkMacSystemFont, Segoe UI, Helvetica Neue, Arial, sans-serif"
    fontSize: "2.75rem"
    fontWeight: 700
    lineHeight: 1.12
    letterSpacing: 0
  headline:
    fontFamily: "Segoe UI Variable, Aptos, -apple-system, BlinkMacSystemFont, Segoe UI, Helvetica Neue, Arial, sans-serif"
    fontSize: "2.2rem"
    fontWeight: 700
    lineHeight: 1.2
    letterSpacing: 0
  title:
    fontFamily: "Segoe UI Variable, Aptos, -apple-system, BlinkMacSystemFont, Segoe UI, Helvetica Neue, Arial, sans-serif"
    fontSize: "1.1rem"
    fontWeight: 600
    lineHeight: 1.35
    letterSpacing: 0
  body:
    fontFamily: "Segoe UI Variable, Aptos, -apple-system, BlinkMacSystemFont, Segoe UI, Helvetica Neue, Arial, sans-serif"
    fontSize: "1rem"
    fontWeight: 400
    lineHeight: 1.7
  label:
    fontFamily: "Segoe UI Variable, Aptos, -apple-system, BlinkMacSystemFont, Segoe UI, Helvetica Neue, Arial, sans-serif"
    fontSize: "0.68rem"
    fontWeight: 700
    lineHeight: 1.4
    letterSpacing: 0
rounded:
  xs: "4px"
  sm: "8px"
  md: "12px"
  lg: "16px"
  xl: "24px"
  pill: "999px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "16px"
  lg: "24px"
  xl: "32px"
  xxl: "40px"
components:
  button-primary:
    backgroundColor: "{colors.primary-blue}"
    textColor: "{colors.white}"
    rounded: "{rounded.md}"
    padding: "8px 18px"
  button-primary-hover:
    backgroundColor: "{colors.primary-blue-dark}"
    textColor: "{colors.white}"
    rounded: "{rounded.md}"
    padding: "8px 18px"
  button-outlined:
    backgroundColor: "{colors.surface-slate}"
    textColor: "{colors.primary-blue-light}"
    rounded: "{rounded.md}"
    padding: "8px 18px"
  card-surface:
    backgroundColor: "{colors.surface-slate}"
    textColor: "{colors.ink-primary}"
    rounded: "{rounded.md}"
    padding: "24px"
  chip-status:
    backgroundColor: "{colors.surface-slate}"
    textColor: "{colors.primary-blue-light}"
    rounded: "{rounded.sm}"
    padding: "4px 10px"
---

# Design System: JejakAgent

## 1. Overview

**Creative North Star: "Secure Command Console"**

JejakAgent should feel like a professional DFIR command surface: dark, focused, technically alive, and built for analysts who need to trust what they see. The product can be futuristic, but its futurism comes from crisp hierarchy, state-rich feedback, evidence density, and disciplined steel-blue accents rather than generic AI visual tropes.

The system rejects the generic blue AI-product look named in PRODUCT.md. It should never read as a soft blue chatbot wrapper, crypto dashboard, or decorative hacker-movie interface. Visual energy is allowed only when it sharpens investigation state: upload readiness, pipeline progress, evidence provenance, severity, confidence, and export actions.

**Key Characteristics:**
- Dark operational canvas with translucent slate panels.
- Calm steel blue as a rare, high-signal action and selection color.
- Indigo, amber, emerald, rose, and blue reserved for semantic system state.
- Dense but readable panels for evidence, sessions, timelines, and report data.
- Motion used for status feedback, not page choreography.

## 2. Colors

The palette is a dark cyber-operational system anchored by calm steel blue, with semantic supporting colors for investigation state and risk.

### Primary
- **Signal Blue**: The primary action and selection color. Use it for primary CTAs, active navigation, progress emphasis, live trace highlights, focus rings, and selected tabs.
- **Mist Blue**: The muted highlight used for active labels, selected tabs, and small icons that need to feel alive without glowing.
- **Deep Signal Blue**: The darker hover color for primary actions and selected-state depth.

### Secondary
- **Forensic Indigo**: The secondary automation color. Use it sparingly for model/provider contexts and non-primary technical accents.
- **Deep Forensic Indigo**: A restrained secondary accent, not a gradient endpoint.

### Tertiary
- **Evidence Blue**: Informational state and neutral investigation status.
- **Verified Emerald**: Success, online readiness, complete states, and confirmed evidence counts.
- **Containment Amber**: Warning, limitations, confidence caveats, local-first notices, and needs-review states.
- **Incident Rose**: Errors, anomalous lines, destructive actions, and high-severity risk.

### Neutral
- **Abyss Background**: The app canvas. It must remain the darkest layer and carry the subtle grid atmosphere.
- **Slate Surface**: The main panel and card base. It uses alpha, borders, and tonal layering; blur is not a default surface treatment.
- **Sidebar Slate**: The darker navigation layer used for drawers, menus, and shell surfaces.
- **Primary Ink**: Main headings, data labels, and high-value evidence text.
- **Secondary Ink**: Body text, descriptions, and table content.
- **Muted Ink**: Secondary metadata, timestamps, helper copy, and inactive tab labels.
- **Subtle Ink**: Low-priority descriptions only; do not use it for important evidence.
- **Slate Border**: Low-contrast borders at reduced opacity for panels and dividers.

### Named Rules

**The Blue Scarcity Rule.** Blue is a signal, not wallpaper. If more than roughly 10% of a task screen is blue, the interface starts looking like generic AI branding.

**The Semantic State Rule.** Emerald, amber, rose, and blue are reserved for meaning. Do not use them as decorative palette variety.

## 3. Typography

**Display Font:** Segoe UI Variable / Aptos with system sans fallbacks.
**Body Font:** Segoe UI Variable / Aptos with system sans fallbacks.
**Label/Mono Font:** Segoe UI Variable / Aptos for labels; system monospace only for session IDs, command traces, log templates, hashes, and evidence strings.

**Character:** The typography is clean, technical, and operational. It should feel like a product UI first: readable labels, compact hierarchy, stable data, and no decorative display font detours.

### Hierarchy
- **Display** (700, 2.75rem, 1.12): Reserved for landing hero and rare top-level page moments.
- **Headline** (700, 2.2rem, 1.2): Primary screen titles such as settings, investigation status, and report overview.
- **Title** (600, 1.1rem, 1.35): Cards, panels, section titles, session items, and component headings.
- **Body** (400, 1rem, 1.7): Explanatory copy, investigation summaries, report text, and form helper text.
- **Label** (700, 0.68rem, 0): Short operational labels, status kickers, and overline metadata. Keep labels short.

### Named Rules

**The Evidence Readability Rule.** Long evidence strings, session IDs, event templates, hashes, and IOC values must wrap safely and stay readable. Never sacrifice log readability for a dramatic heading.

**The Product Scale Rule.** Product screens use fixed rem sizes and restrained hierarchy. Fluid hero-sized typography belongs only to the landing surface.

## 4. Elevation

JejakAgent uses tonal layering, translucent surfaces, crisp borders, and restrained state outlines. Depth is structural on hover or focus. The default state should feel stable, not floaty.

### Shadow Vocabulary
- **Surface Border** (`box-shadow: none; border: 1px solid rgba(148, 163, 184, 0.18)`): Main panels, cards, dialogs, and large content surfaces.
- **Primary Action Rest** (`box-shadow: none; background: #2563eb`): Primary contained buttons at rest.
- **Primary Action Hover** (`box-shadow: none; background: #1d4ed8`): Primary contained buttons on hover.
- **Drag / Active Upload Outline** (`box-shadow: 0 0 0 1px rgba(147, 197, 253, 0.24)`): Dropzone active state only.
- **Terminal Surface** (`box-shadow: none; border: 1px solid rgba(147, 197, 253, 0.14)`): Live agent terminal and deep inspection surfaces.

### Named Rules

**The State Highlight Rule.** Highlights must explain state: selected, active, online, processing, error, or hover. Decorative glow without state is prohibited.

## 5. Components

### Buttons

- **Shape:** Rounded operational controls (12px radius) for normal actions; larger CTA buttons may use pill-like geometry only on landing.
- **Primary:** Solid Signal Blue, white text, 8px 18px padding, 600 weight.
- **Hover / Focus:** Hover darkens toward Deep Signal Blue. Focus must remain visibly outlined even on dark surfaces.
- **Secondary / Ghost / Tertiary:** Outlined buttons use translucent Slate Surface, mist-blue text, and a low-alpha mist-blue border. Text buttons are muted until hover.

### Chips

- **Style:** Compact status capsules with 8px radius, 600+ font weight, translucent background, and semantic color text.
- **State:** Use chips for system online, severity, confidence, evidence IDs, provider health, and export formats. A chip should represent data or state, not decoration.

### Cards / Containers

- **Corner Style:** Major surfaces use 12px radius; tighter report panels use 8px to 12px depending on density.
- **Background:** Slate Surface over Abyss Background with alpha and border-based separation.
- **Shadow Strategy:** Prefer borders and tonal layering; reserve outlines for interaction state.
- **Border:** 1px low-alpha Slate Border is standard.
- **Internal Padding:** 24px to 40px for major cards; 16px to 20px for dense report and sidebar elements.

### Inputs / Fields

- **Style:** MUI fields should sit on translucent slate, with rounded corners and low-alpha borders.
- **Focus:** Focus border shifts toward Signal Blue and must be visible on dark panels.
- **Error / Disabled:** Error uses Incident Rose. Disabled controls must reduce contrast without disappearing.

### Navigation

- **Style:** Persistent dark sidebar plus fixed translucent app bar. Navigation items use 10px radius, 44px minimum height, and icon-led labels.
- **Active State:** Selected items use low-alpha blue fill, mist-blue text, and a full border treatment.
- **Mobile Treatment:** The sidebar collapses to a temporary drawer. Main content must keep full-width task flow and avoid horizontal overflow.

### Dropzone

The upload dropzone is the onboarding workhorse. It uses a 2px dashed mist-blue border, large upload icon, and active drag outline. Keep the interaction direct: file first, then full investigation or quick analysis.

### Investigation Pipeline

The investigation surface uses progress bars, steppers, stat cards, and agent terminal output. Status must be explicit and chronological. The terminal styling can feel cyber-forward, but log lines must remain scannable and wrap safely.

### Report Dashboard

Report panels are dense, tabbed, evidence-first components. Tabs should be icon-led, selected state blue, and panels should protect long evidence text with `overflow-wrap: anywhere`.

## 6. Do's and Don'ts

### Do:

- **Do** use Signal Blue for primary actions, selected states, progress emphasis, and live trace highlights.
- **Do** keep product screens dense, operational, and familiar; this is an analyst workspace, not a marketing animation reel.
- **Do** use semantic colors consistently: emerald for verified/success, amber for caution, rose for error or high risk, blue for info.
- **Do** preserve readable contrast for body text, report tables, event templates, session IDs, and IOC values.
- **Do** use motion for state changes, loading, upload drag, progress, and feedback in the 150-250ms range.
- **Do** keep evidence provenance, limitations, severity, confidence, and export actions visible and auditable.

### Don't:

- **Don't** use generic blue AI-product styling: soft blue gradients, abstract AI glow, vague automation language, or visuals that could belong to any chatbot or SaaS dashboard.
- **Don't** turn the interface into a crypto dashboard, neon hacker-movie surface, or decorative sci-fi screen.
- **Don't** use blue as page wallpaper. If everything is tinted, nothing is a signal.
- **Don't** add decorative motion that does not convey state.
- **Don't** hide uncertainty or limitations behind polished copy. Analyst trust depends on visible caveats.
- **Don't** let long evidence strings, hashes, file names, or event templates overflow their containers.
