import express from "express";
import cors from "cors";
const PORT = Number(process.env.PORT || 4105);
const app = express();
app.use(cors()); app.use(express.json());
app.get("/health", (_req, res) => res.json({ service: "policy", status: "ok", pillar: "atlas" }));
app.listen(PORT, () => console.log("policy listening on http://localhost:" + PORT));
