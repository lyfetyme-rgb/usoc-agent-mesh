import express from "express";
import cors from "cors";
const PORT = Number(process.env.PORT || 4113);
const app = express();
app.use(cors()); app.use(express.json());
app.get("/health", (_req, res) => res.json({ service: "observability", status: "ok", pillar: "atlas" }));
app.listen(PORT, () => console.log("observability listening on http://localhost:" + PORT));
