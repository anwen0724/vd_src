from __future__ import annotations

import json
from pathlib import Path

from method.ours.permission_check_targets.schema import PermissionCheckTargets, TargetGenerationDiagnostics


def write_permission_target_outputs(
    targets: PermissionCheckTargets,
    diagnostics: TargetGenerationDiagnostics,
    out_dir: str | Path,
) -> tuple[Path, Path]:
    output_dir = Path(out_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    targets_path = output_dir / "permission_check_targets.json"
    diagnostics_path = output_dir / "target_generation_diagnostics.json"
    targets_path.write_text(
        json.dumps(targets.to_json_dict(), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    diagnostics_path.write_text(
        json.dumps(diagnostics.to_json_dict(), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return targets_path, diagnostics_path
