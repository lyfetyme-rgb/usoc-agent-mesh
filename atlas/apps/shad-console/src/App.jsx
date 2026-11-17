import React, { useEffect, useState } from "react";

const API = "/shad";

export default function App() {
  const [events, setEvents] = useState([]);
  const [verify, setVerify] = useState(null);
  const [result, setResult] = useState(null);
  const [form, setForm] = useState({
    tenantId: "customer-001",
    modelId: "atlas-rul-chiller-v4",
    modelVersion: "4.2.1",
    action: "Increase compressor output",
    confidence: 0.9,
    assetHealthOk: false,
    physicalEnvelopeOk: false,
    cyberRisk: 0.1,
  });

  async function load() {
    const r = await fetch(`${API}/events?tenantId=customer-001&limit=50`);
    const d = await r.json();
    setEvents(d.events || []);
    const v = await fetch(`${API}/verify?tenantId=customer-001`);
    setVerify(await v.json());
  }

  useEffect(() => { load(); }, []);

  async function submitCmd() {
    const cmd = {
      tenantId: form.tenantId,
      modelId: form.modelId,
      modelVersion: form.modelVersion,
      action: form.action,
      confidence: Number(form.confidence),
      dataIntegrityOk: true,
      modelIntegrityOk: true,
      poisoningDetected: false,
      biasDetected: false,
      driftDetected: false,
      assetHealthOk: form.assetHealthOk,
      physicalEnvelopeOk: form.physicalEnvelopeOk,
      cyberRisk: Number(form.cyberRisk),
      actor: { type: "MODEL", id: "atlas-rul" },
    };
    const r = await fetch(`${API}/trust-funnel`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(cmd),
    });
    setResult(await r.json());
    load();
  }

  return (
    <div style={{ fontFamily: "system-ui", padding: 20, maxWidth: 1100, margin: "0 auto" }}>
      <h1>Atlas BENGAL SHAD Console</h1>
      <p>AI Assurance &amp; Cyber-Defense Observability (read-only over SHAD backend)</p>

      <section style={{ display: "flex", gap: 20, flexWrap: "wrap" }}>
        <div style={{ flex: 1, minWidth: 260, padding: 12, border: "1px solid #ddd", borderRadius: 8 }}>
          <h3>Audit Chain</h3>
          <p>Events: {events.length}</p>
          <p>Integrity: {verify ? (verify.ok ? "OK" : "BROKEN") : "..."}</p>
        </div>
        <div style={{ flex: 1, minWidth: 260, padding: 12, border: "1px solid #ddd", borderRadius: 8 }}>
          <h3>KPIs</h3>
          <p>Commands evaluated: {events.filter(e => e.eventType === "POLICY_EVALUATION" || e.eventType === "COMMAND_BLOCKED").length}</p>
          <p>Blocked: {events.filter(e => e.eventType === "COMMAND_BLOCKED").length}</p>
          <p>Drift events: {events.filter(e => e.eventType === "MODEL_DRIFT").length}</p>
        </div>
      </section>

      <section style={{ marginTop: 20, padding: 12, border: "1px solid #ddd", borderRadius: 8 }}>
        <h3>Trust Funnel Evaluation</h3>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
          <label>Tenant <input value={form.tenantId} onChange={e => setForm({ ...form, tenantId: e.target.value })} /></label>
          <label>Model <input value={form.modelId} onChange={e => setForm({ ...form, modelId: e.target.value })} /></label>
          <label>Version <input value={form.modelVersion} onChange={e => setForm({ ...form, modelVersion: e.target.value })} /></label>
          <label>Action <input value={form.action} onChange={e => setForm({ ...form, action: e.target.value })} /></label>
          <label>Confidence <input type="number" step="0.1" value={form.confidence} onChange={e => setForm({ ...form, confidence: e.target.value })} /></label>
          <label>Cyber risk <input type="number" step="0.1" value={form.cyberRisk} onChange={e => setForm({ ...form, cyberRisk: e.target.value })} /></label>
          <label>Asset healthy <input type="checkbox" checked={form.assetHealthOk} onChange={e => setForm({ ...form, assetHealthOk: e.target.checked })} /></label>
          <label>Physical envelope ok <input type="checkbox" checked={form.physicalEnvelopeOk} onChange={e => setForm({ ...form, physicalEnvelopeOk: e.target.checked })} /></label>
        </div>
        <button onClick={submitCmd} style={{ marginTop: 10 }}>Evaluate Command</button>
        {result && (
          <div style={{ marginTop: 10 }}>
            <strong>Decision: {result.decision}</strong> (risk {result.riskScore?.toFixed(3)})
            <ul>{result.reasons?.map((r, i) => <li key={i}>{r}</li>)}</ul>
            <details>
              <summary>Stages</summary>
              <ul>{result.stages?.map((s, i) => <li key={i}>{s.name}: {s.passed ? "PASS" : "FAIL"} — {s.detail}</li>)}</ul>
            </details>
          </div>
        )}
      </section>

      <section style={{ marginTop: 20 }}>
        <h3>Recent SHAD Events</h3>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead><tr><th>Time</th><th>Tenant</th><th>Type</th><th>Severity</th><th>Risk</th><th>Action</th></tr></thead>
          <tbody>
            {events.map((e) => (
              <tr key={e.eventId}>
                <td>{new Date(e.timestamp).toLocaleString()}</td>
                <td>{e.tenantId}</td>
                <td>{e.eventType}</td>
                <td>{e.severity}</td>
                <td>{e.riskScore?.toFixed(2)}</td>
                <td>{e.resolvedAction}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}