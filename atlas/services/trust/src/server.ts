import express from "express";
import cors from "cors";
const PORT = Number(process.env.PORT || 4101);
const app = express();
app.use(cors()); app.use(express.json());
app.get("/health", (_req, res) => res.json({ service: "trust", status: "ok", pillar: "atlas" }));
app.listen(PORT, () => console.log("trust listening on http://localhost:" + PORT));
