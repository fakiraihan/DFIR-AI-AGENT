"""Parsing profile selection service."""

from pathlib import Path

from app_context import BASE_DIR


def resolve_config_path(raw_path: str) -> Path:
    path_obj = Path(raw_path)
    if path_obj.is_absolute():
        return path_obj
    return (BASE_DIR / path_obj).resolve()


def build_model_profile(name: str, settings) -> dict:
    if name == "windows_sysmon":
        return {
            "name": "windows_sysmon",
            "model_path": resolve_config_path(settings.windows_sysmon_deeplog_model_path),
            "vocab_path": resolve_config_path(settings.windows_sysmon_deeplog_vocab_path),
            "window_size": settings.windows_sysmon_deeplog_window_size,
            "topk": getattr(settings, "windows_sysmon_deeplog_topk", getattr(settings, "deeplog_topk", 3)),
            "template_strategy": settings.windows_sysmon_parser_template_strategy,
            "template_enrichment": getattr(settings, "windows_sysmon_deeplog_template_enrichment", "none"),
        }

    if name == "windows_evtx":
        return {
            "name": "windows_evtx",
            "model_path": resolve_config_path(settings.windows_evtx_deeplog_model_path),
            "vocab_path": resolve_config_path(settings.windows_evtx_deeplog_vocab_path),
            "window_size": settings.windows_evtx_deeplog_window_size,
            "topk": settings.windows_evtx_deeplog_topk,
            "template_strategy": settings.windows_evtx_parser_template_strategy,
            "template_enrichment": getattr(settings, "windows_evtx_deeplog_template_enrichment", "none"),
            "use_bos_context": settings.windows_evtx_deeplog_use_bos_context,
            "bos_token": settings.windows_evtx_deeplog_bos_token,
            "bos_count": settings.windows_evtx_deeplog_bos_count,
        }

    if name == "lmd_enriched":
        return {
            "name": "lmd_enriched",
            "model_path": resolve_config_path(settings.lmd_enriched_deeplog_model_path),
            "vocab_path": resolve_config_path(settings.lmd_enriched_deeplog_vocab_path),
            "window_size": settings.lmd_enriched_deeplog_window_size,
            "topk": settings.lmd_enriched_deeplog_topk,
            "template_strategy": settings.windows_sysmon_parser_template_strategy,
            "template_enrichment": settings.lmd_enriched_deeplog_template_enrichment,
        }

    if name == "linux_log":
        return {
            "name": "linux_log",
            "model_path": resolve_config_path(settings.linux_log_deeplog_model_path),
            "vocab_path": resolve_config_path(settings.linux_log_deeplog_vocab_path),
            "window_size": settings.linux_log_deeplog_window_size,
            "topk": settings.linux_log_deeplog_topk,
            "template_strategy": settings.linux_log_parser_template_strategy,
            "template_enrichment": getattr(
                settings,
                "linux_log_deeplog_template_enrichment",
                "none",
            ),
        }

    return {
        "name": "general",
        "model_path": resolve_config_path(settings.deeplog_model_path),
        "vocab_path": resolve_config_path(settings.deeplog_vocab_path),
        "window_size": settings.deeplog_window_size,
        "topk": getattr(settings, "deeplog_topk", 3),
        "template_strategy": settings.parser_template_strategy,
        "template_enrichment": getattr(settings, "deeplog_template_enrichment", "none"),
    }


def apply_template_enrichment(parsed_df, templates, enrichment_mode):
    from modules.deeplog_template_enrichment import (
        enrich_structured_dataframe,
        is_enrichment_enabled,
        summarize_templates,
    )

    if not is_enrichment_enabled(enrichment_mode):
        return parsed_df, templates

    enriched_df = enrich_structured_dataframe(
        parsed_df,
        mode=enrichment_mode,
        preserve_original_template=True,
    )
    if "event_template" in enriched_df.columns:
        enriched_df["EventTemplate"] = enriched_df["event_template"]
    enriched_templates = summarize_templates(enriched_df)
    return enriched_df, enriched_templates


def is_windows_sysmon_evtx(file_path: str, parsed_df) -> bool:
    suffix = Path(file_path).suffix.lower()
    if suffix != ".evtx" or parsed_df.empty or "raw_line" not in parsed_df.columns:
        return False

    raw_lines = parsed_df["raw_line"].astype(str)
    windows_sysmon_ratio = raw_lines.str.contains(
        "Microsoft-Windows-Sysmon", regex=False
    ).mean()
    return bool(windows_sysmon_ratio >= 0.5)


def is_linux_log_text(file_path: str, sample_lines: int = 200) -> bool:
    from modules.linux_log_templates import classify_linux_log_path, classify_linux_log_source

    path_obj = Path(file_path)
    if classify_linux_log_path(path_obj) is None:
        return False

    seen = 0
    matches = 0
    try:
        with open(path_obj, "r", encoding="utf-8", errors="ignore") as file_obj:
            for line in file_obj:
                raw_line = line.strip().lstrip("\ufeff")
                if not raw_line:
                    continue

                seen += 1
                if classify_linux_log_source(path_obj, raw_line):
                    matches += 1

                if seen >= sample_lines:
                    break
    except OSError:
        return False

    if seen == 0:
        return False

    required_matches = max(1, min(5, seen))
    return matches >= required_matches and (matches / seen) >= 0.3


def parse_with_profile(file_path: str, settings, max_lines=None):
    from modules.parsing import parse_log_file

    is_evtx_path = Path(file_path).suffix.lower() == ".evtx"

    if is_linux_log_text(file_path):
        linux_profile = build_model_profile("linux_log", settings)
        if linux_profile["model_path"].exists() and linux_profile["vocab_path"].exists():
            parsed_df, templates = parse_log_file(
                file_path,
                depth=settings.drain_depth,
                sim_threshold=settings.drain_sim_threshold,
                max_children=settings.drain_max_children,
                template_strategy=linux_profile["template_strategy"],
                max_lines=max_lines,
            )
            parsed_df, templates = apply_template_enrichment(
                parsed_df,
                templates,
                linux_profile.get("template_enrichment", "none"),
            )
            return parsed_df, templates, linux_profile

    general_profile = build_model_profile("general", settings)
    parsed_df, templates = parse_log_file(
        file_path,
        depth=settings.drain_depth,
        sim_threshold=settings.drain_sim_threshold,
        max_children=settings.drain_max_children,
        template_strategy=general_profile["template_strategy"],
        max_lines=max_lines,
    )

    selected_profile = general_profile
    if is_windows_sysmon_evtx(file_path, parsed_df):
        windows_sysmon_profile = build_model_profile("windows_sysmon", settings)
        parsed_df, templates = parse_log_file(
            file_path,
            depth=settings.drain_depth,
            sim_threshold=settings.drain_sim_threshold,
            max_children=settings.drain_max_children,
            template_strategy=windows_sysmon_profile["template_strategy"],
            max_lines=max_lines,
        )
        selected_profile = windows_sysmon_profile
    elif is_evtx_path and getattr(settings, "evtx_general_deeplog_profile", "general") == "windows_evtx":
        windows_evtx_profile = build_model_profile("windows_evtx", settings)
        parsed_df, templates = parse_log_file(
            file_path,
            depth=settings.drain_depth,
            sim_threshold=settings.drain_sim_threshold,
            max_children=settings.drain_max_children,
            template_strategy=windows_evtx_profile["template_strategy"],
            max_lines=max_lines,
        )
        selected_profile = windows_evtx_profile

    parsed_df, templates = apply_template_enrichment(
        parsed_df,
        templates,
        selected_profile.get("template_enrichment", "none"),
    )
    return parsed_df, templates, selected_profile
