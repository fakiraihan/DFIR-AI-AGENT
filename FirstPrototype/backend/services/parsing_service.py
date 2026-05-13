"""Parsing profile selection service."""

from pathlib import Path

from app_context import BASE_DIR


def resolve_config_path(raw_path: str) -> Path:
    path_obj = Path(raw_path)
    if path_obj.is_absolute():
        return path_obj
    return (BASE_DIR / path_obj).resolve()


def build_model_profile(name: str, settings) -> dict:
    if name == "sysmon":
        return {
            "name": "sysmon",
            "model_path": resolve_config_path(settings.sysmon_deeplog_model_path),
            "vocab_path": resolve_config_path(settings.sysmon_deeplog_vocab_path),
            "window_size": settings.sysmon_deeplog_window_size,
            "template_strategy": settings.sysmon_parser_template_strategy,
        }

    return {
        "name": "general",
        "model_path": resolve_config_path(settings.deeplog_model_path),
        "vocab_path": resolve_config_path(settings.deeplog_vocab_path),
        "window_size": settings.deeplog_window_size,
        "template_strategy": settings.parser_template_strategy,
    }


def is_sysmon_evtx(file_path: str, parsed_df) -> bool:
    suffix = Path(file_path).suffix.lower()
    if suffix != ".evtx" or parsed_df.empty or "raw_line" not in parsed_df.columns:
        return False

    raw_lines = parsed_df["raw_line"].astype(str)
    sysmon_ratio = raw_lines.str.contains(
        "Microsoft-Windows-Sysmon", regex=False
    ).mean()
    return bool(sysmon_ratio >= 0.5)


def parse_with_profile(file_path: str, settings, max_lines=None):
    from modules.parsing import parse_log_file

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
    if is_sysmon_evtx(file_path, parsed_df):
        sysmon_profile = build_model_profile("sysmon", settings)
        parsed_df, templates = parse_log_file(
            file_path,
            depth=settings.drain_depth,
            sim_threshold=settings.drain_sim_threshold,
            max_children=settings.drain_max_children,
            template_strategy=sysmon_profile["template_strategy"],
            max_lines=max_lines,
        )
        selected_profile = sysmon_profile

    return parsed_df, templates, selected_profile
