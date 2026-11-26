#!/usr/bin/env python3
"""Render a Kustomize overlay with images pinned to signed digests.

`kubectl apply -k` re-applies the tag from the manifest on every deploy, which
would undo any post-apply `kubectl set image`. This tool renders the overlay to
a single multi-document YAML and rewrites container images *before* apply so the
exact cosign-verified digests are what reach the cluster.

Only images belonging to the two USOC artifacts are rewritten, and the script
fails if either artifact is absent from the rendered manifests.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

WORKLOAD_KINDS = {"Deployment", "Job", "CronJob", "DaemonSet", "StatefulSet", "ReplicaSet"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("overlay", type=Path, help="Kustomize overlay directory")
    parser.add_argument("--mesh-image", required=True, help="Signed usoc-mesh image by digest")
    parser.add_argument("--dashboard-image", required=True, help="Signed usoc-dashboard image by digest")
    parser.add_argument("--output", type=Path, help="Write YAML here instead of stdout")
    return parser.parse_args()


def validate_image(value: str, label: str) -> None:
    if "@sha256:" not in value:
        raise ValueError(f"{label} must be pinned to a sha256 digest: {value!r}")


def iter_containers(doc: dict[str, Any]) -> list[dict[str, Any]]:
    if doc.get("kind") not in WORKLOAD_KINDS:
        return []
    spec = doc.get("spec", {})
    if doc.get("kind") == "CronJob":
        spec = spec.get("jobTemplate", {}).get("spec", {}).get("template", {}).get("spec", {})
    else:
        spec = spec.get("template", {}).get("spec", {})
    containers = list(spec.get("containers", []))
    containers.extend(spec.get("initContainers", []))
    return [item for item in containers if isinstance(item, dict)]


def pin_images(
    docs: list[dict[str, Any]], mesh_image: str, dashboard_image: str
) -> tuple[list[dict[str, Any]], int, int]:
    mesh_count = 0
    dashboard_count = 0
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        for container in iter_containers(doc):
            image = str(container.get("image", ""))
            if image.startswith("ghcr.io/lyfetyme-rgb/usoc-mesh"):
                container["image"] = mesh_image
                mesh_count += 1
            elif image.startswith("ghcr.io/lyfetyme-rgb/usoc-dashboard"):
                container["image"] = dashboard_image
                dashboard_count += 1
    return docs, mesh_count, dashboard_count


def main() -> int:
    args = parse_args()
    try:
        validate_image(args.mesh_image, "--mesh-image")
        validate_image(args.dashboard_image, "--dashboard-image")
        rendered = subprocess.run(
            ["kubectl", "kustomize", str(args.overlay)],
            check=True,
            capture_output=True,
            text=True,
        )
        docs = [doc for doc in yaml.safe_load_all(rendered.stdout) if doc is not None]
        docs, mesh_count, dashboard_count = pin_images(
            docs, args.mesh_image, args.dashboard_image
        )
        if mesh_count == 0 or dashboard_count == 0:
            raise ValueError(
                "overlay did not contain both artifacts "
                f"(mesh={mesh_count}, dashboard={dashboard_count})"
            )
        output = yaml.safe_dump_all(docs, sort_keys=False)
        if args.output:
            args.output.write_text(output, encoding="utf-8")
        else:
            sys.stdout.write(output)
    except (OSError, subprocess.CalledProcessError, ValueError, yaml.YAMLError) as exc:
        print(f"render_overlay failed: {exc}", file=sys.stderr)
        return 1
    print(
        f"rendered {len(docs)} resources; pinned mesh={mesh_count}, dashboard={dashboard_count}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
