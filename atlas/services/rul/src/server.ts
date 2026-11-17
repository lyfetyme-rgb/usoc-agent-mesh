import express from "express";
import cors from "cors";
const PORT = Number(process.env.PORT || 4110);
const app = express();
app.use(cors()); app.use(express.json());
app.get("/health", (_req, res) => res.json({ service: "rul", status: "ok", pillar: "atlas" }));
app.listen(PORT, () => console.log("rul listening on http://localhost:" + PORT));
