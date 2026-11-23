"""Guardrails for the Kubernetes deployment scaffold.

These tests treat the manifests as code: they fail if a future edit reintroduces
a privileged container, a browser-visible token, a per-pod evidence volume, or
an env var that USOC's Settings does not read. No cluster is required.
"""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
K8S = ROOT / "deploy" / "kubernetes"
MANIFESTS = sorted(K8S.glob("*.yaml"))
EXAMPLES = sorted(K8S.glob("*.example"))


def load_manifests() -> list[dict]:
    docs: list[dict] = []
    for path in MANIFESTS:
        for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")):
            if doc:
                doc["_source"] = path.name
                docs.append(doc)
    return docs


DOCS = load_manifests()


def by_kind(kind: str) -> list[dict]:
    return [doc for doc in DOCS if doc.get("kind") == kind]


def pod_specs() -> list[tuple[str, dict, dict]]:
    """(source, pod spec, container) for every container in a workload."""
    out: list[tuple[str, dict, dict]] = []
    for doc in by_kind("Deployment"):
        spec = doc["spec"]["template"]["spec"]
        for container in spec["containers"]:
            out.append((doc["_source"], spec, container))
    return out


def test_manifest_set_is_parseable_and_scoped_to_one_namespace():
    assert {p.name for p in MANIFESTS} >= {
        "00-namespace.yaml",
        "02-configmap.yaml",
        "03-storage.yaml",
        "10-control-plane.yaml",
        "11-workers.yaml",
        "20-network-policies.yaml",
        "30-dashboard-proxy.yaml",
    }
    # Templates carry a .example suffix so `kubectl apply -f .` never creates
    # a usable-looking Secret or an unauthenticated public Ingress.
    assert {p.name for p in EXAMPLES} == {
        "01-secrets.example.yaml.example",
        "31-ingress.yaml.example",
    }
    assert DOCS
    for doc in DOCS:
        assert doc.get("apiVersion"), doc
        assert doc.get("kind"), doc
        if doc["kind"] != "Namespace":
            assert doc.get("metadata", {}).get("namespace") == "usoc-prod", doc


def test_no_invented_backend_env_vars_or_latest_images():
    """Postgres/S3 backends do not exist; silence here would be dangerous."""
    forbidden = {"DATABASE_URL", "EVIDENCE_S3_BUCKET", "REDIS_URL", "POSTGRES_URL"}
    for source, _spec, container in pod_specs():
        names = {env.get("name") for env in container.get("env", [])}
        assert not (names & forbidden), (source, names & forbidden)
        assert not container["image"].endswith(":latest"), source


def test_every_container_keeps_the_section_6_hardening_invariants():
    for source, spec, container in pod_specs():
        pod_security = spec.get("securityContext", {})
        assert pod_security.get("runAsNonRoot") is True, source
        assert pod_security.get("seccompProfile", {}).get("type") == "RuntimeDefault", source
        assert spec.get("automountServiceAccountToken") is False, source
        assert not spec.get("hostNetwork"), source
        for volume in spec.get("volumes", []):
            assert "hostPath" not in volume, (source, volume)

        container_security = container.get("securityContext", {})
        assert container_security.get("readOnlyRootFilesystem") is True, source
        assert container_security.get("allowPrivilegeEscalation") is False, source
        assert container_security.get("privileged") is False, source
        assert "ALL" in container_security.get("capabilities", {}).get("drop", []), source

        mounts = {mount["mountPath"] for mount in container.get("volumeMounts", [])}
        assert "/tmp" in mounts, source
        assert any(
            volume["name"] == "tmp-scratch" and "emptyDir" in volume
            for volume in spec.get("volumes", [])
        ), source


def test_shared_evidence_volume_is_a_rwx_pvc_not_a_per_pod_disk():
    pvc = [doc for doc in by_kind("PersistentVolumeClaim") if doc["metadata"]["name"] == "usoc-mesh-data"]
    assert len(pvc) == 1
    assert "ReadWriteMany" in pvc[0]["spec"]["accessModes"]

    data_mounts = 0
    for source, spec, container in pod_specs():
        for mount in container.get("volumeMounts", []):
            if mount["mountPath"] != "/data":
                continue
            data_mounts += 1
            volumes = [v for v in spec["volumes"] if v["name"] == mount["name"]]
            assert len(volumes) == 1, source
            assert volumes[0].get("persistentVolumeClaim", {}).get("claimName") == "usoc-mesh-data", source
    assert data_mounts >= 3  # control plane + both example workers


def test_tokens_are_mounted_files_and_never_inline_env_values():
    for source, _spec, container in pod_specs():
        names = {env.get("name") for env in container.get("env", [])}
        assert "AGENT_HEALTH_TOKEN" not in names, source
        assert "AGENT_SHARED_SECRET" not in names, source
        assert "AGENT_ADMIN_TOKEN" not in names, source
        if "AGENT_HEALTH_TOKEN_FILE" in names:
            mounts = {m["mountPath"] for m in container.get("volumeMounts", [])}
            assert "/run/secrets" in mounts, source
        for env in container.get("env", []):
            if "valueFrom" in env:
                ref = list(env["valueFrom"].values())[0]
                assert ref.get("name") == "usoc-mesh-secrets", (source, env)


def test_probes_use_the_secret_aware_cli_and_no_bearer_literal():
    for source, _spec, container in pod_specs():
        if not container["image"].endswith("usoc-mesh:0.2.0"):
            continue
        for key in ("livenessProbe", "readinessProbe"):
            command = container[key]["exec"]["command"]
            assert "agents" in command and "probe" in command, (source, key)
            assert any("--url" in item for item in command), (source, key)
        assert not any("Bearer" in str(v) for v in container.get("env", [])), source


def test_control_plane_is_single_writer_and_only_workers_scale():
    control = [doc for doc in by_kind("Deployment") if doc["metadata"]["name"] == "usoc-mesh"]
    assert len(control) == 1
    assert control[0]["spec"]["replicas"] == 1
    assert control[0]["spec"]["strategy"]["type"] == "Recreate"

    targets = {
        hpa["spec"]["scaleTargetRef"]["name"]
        for hpa in by_kind("HorizontalPodAutoscaler")
    }
    assert targets
    assert "usoc-mesh" not in targets
    assert all(name.endswith("-worker") for name in targets), targets


def test_network_policies_deny_by_default_and_allow_no_wildcard_egress():
    policies = {doc["metadata"]["name"]: doc for doc in by_kind("NetworkPolicy")}
    assert "default-deny-ingress" in policies
    assert "default-deny-egress" in policies
    for name, doc in policies.items():
        assert "Ingress" in doc["spec"]["policyTypes"] or "Egress" in doc["spec"]["policyTypes"]
        for rule in doc["spec"].get("egress", []):
            for peer in rule.get("to", []):
                assert "ipBlock" not in peer or peer["ipBlock"]["cidr"] != "0.0.0.0/0", name

    assert "allow-dashboard-ingress" in policies
    mesh_ingress = policies["allow-mesh-ingress"]["spec"]["ingress"]
    assert any(
        "podSelector" in peer and peer["podSelector"]["matchLabels"].get("app") == "dashboard-proxy"
        for rule in mesh_ingress
        for peer in rule.get("from", [])
    )


def test_shared_config_uses_real_settings_and_no_secret_values():
    config = [doc for doc in by_kind("ConfigMap") if doc["metadata"]["name"] == "usoc-mesh-config"]
    assert len(config) == 1
    data = config[0]["data"]
    assert data["AGENT_BUS"] == "redis"
    assert data["AGENT_WORKSPACE"] == "/data/workspace"
    assert data["AGENT_REQUIRE_APPROVER_ALLOWLIST"] == "true"
    assert "AGENT_STRICT_PROD" not in data  # opt-in only after trust files exist

    assert not by_kind("Secret"), "real Secrets must not live in the repo"
    secret_template = next(
        yaml.safe_load_all((K8S / "01-secrets.example.yaml.example").read_text(encoding="utf-8"))
    )
    assert all(
        "REPLACE_ME" in str(value)
        for value in secret_template["stringData"].values()
    ), "the example Secret must not contain usable values"


def test_dashboard_image_and_proxy_are_wired_without_exposing_diagnostics():
    proxy = [doc for doc in by_kind("Deployment") if doc["metadata"]["name"] == "usoc-dashboard-proxy"]
    assert len(proxy) == 1
    container = proxy[0]["spec"]["template"]["spec"]["containers"][0]
    assert container["image"].startswith("ghcr.io/") and "usoc-dashboard" in container["image"]
    env = {item["name"]: item.get("value") for item in container["env"]}
    assert env["USOC_DASHBOARD_HOST"] == "0.0.0.0"
    assert "usoc-dashboard" in env["USOC_DASHBOARD_ALLOWED_HOSTS"]
    assert "AGENT_ADMIN_TOKEN_FILE" not in env
    # A kubelet httpGet probe would present a pod-IP Host header and be rejected
    # by the allowlist; probes must use loopback instead.
    for key in ("livenessProbe", "readinessProbe"):
        assert container[key]["exec"]["command"][2].startswith(
            "import urllib.request"
        ), key
        assert "127.0.0.1:8090/api/status" in container[key]["exec"]["command"][2]
    service = [doc for doc in by_kind("Service") if doc["metadata"]["name"] == "usoc-dashboard"]
    assert service[0]["spec"]["type"] == "ClusterIP"

    dashboard_dockerfile = (ROOT / "Dockerfile.dashboard").read_text(encoding="utf-8")
    assert "USER usoc" in dashboard_dockerfile
    assert "COPY dashboard /app/dashboard" in dashboard_dockerfile
