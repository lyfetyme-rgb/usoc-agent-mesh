import express from "express";
import cors from "cors";

const PORT = Number(process.env.GATEWAY_PORT || 4002);
const SHAD_URL = process.env.SHAD_URL || "http://localhost:4001";

const app = express();
app.use(cors());
app.use(express.json());

app.get("/health", (_req, res) => res.json({ service: "command-gateway", status: "ok", shad: SHAD_URL }));

app.post("/gateway/execute", async (req, res) => {
  // Forward proposed command to SHAD trust funnel for assurance
  const r = await fetch(`${SHAD_URL}/shad/trust-funnel`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(req.body),
  });
  const data = await r.json();
  const allowed = data.decision === "ALLOW";
  if (!allowed) {
    return res.status(403).json({ allowed: false, decision: data.decision, reasons: data.reasons, riskScore: data.riskScore });
  }
  // In production, here we would dispatch to edge/BAS. For now, acknowledge.
  res.json({ allowed: true, decision: "ALLOW", message: "command forwarded to edge runtime (simulated)", riskScore: data.riskScore });
});

app.listen(PORT, () => console.log(`Command Gateway listening on http://localhost:${PORT}`));
