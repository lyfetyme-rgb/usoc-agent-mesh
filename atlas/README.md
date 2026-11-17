# Atlas Platform — BENGAL SHAD Edition

Atlas is a cyber-physical AI platform for HVAC/BAS/IoT. BENGAL SHAD is a
cross-cutting AI governance, cyber-defense, and assurance layer that operates
across all six architectural pillars (Data Fabric, Intelligence, Edge/OT,
Trust, Risk, Decision/Safety/Policy).

## Quickstart (local)

```powershell
cd atlas
npm install
# Terminal 1: SHAD backend
npm run dev:shad
# Terminal 2: command gateway
npm run dev:gateway
# Terminal 3: SHAD console
npm run dev:console
```

- SHAD API: http://localhost:4001
- Command Gateway: http://localhost:4002
- SHAD Console: http://localhost:5173

## Key endpoints

- `GET /health`
- `POST /shad/events` append hash-chained audit event
- `GET /shad/events?tenantId=...`
- `GET /shad/verify?tenantId=...`
- `POST /shad/risk`
- `POST /shad/trust-funnel` evaluate a proposed command
- `POST /shad/gateway` gateway-framed evaluation
- `POST /gateway/execute` command gateway enforcement

## Architecture

See `docs/architecture.md`. Repository layout follows the Atlas evolution spec:
`apps/`, `services/`, `edge/`, `packages/`, `infrastructure/`, `security/`, `tests/`, `docs/`.
