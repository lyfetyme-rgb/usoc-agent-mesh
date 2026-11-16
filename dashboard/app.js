const $ = id => document.getElementById(id);
const set = (id, value) => { $(id).textContent = value ?? "—"; };
function tick() {
  const now = new Date();
  set("clock", now.toLocaleTimeString(undefined, {hour12:false}));
  set("date", now.toLocaleDateString(undefined, {weekday:"short",year:"numeric",month:"short",day:"numeric"}).toUpperCase());
}
tick(); setInterval(tick, 1000);
$("theme").addEventListener("click", () => {
  document.body.classList.toggle("light");
  $("theme").textContent = document.body.classList.contains("light") ? "◑ DARK" : "◐ LIGHT";
});
async function refresh() {
  try {
    const response = await fetch("/api/status", {cache:"no-store"});
    if (!response.ok) throw new Error("unavailable");
    const {health, ready} = await response.json();
    set("sync", "LIVE STATUS"); set("updated", `Updated ${new Date().toLocaleTimeString()}`);
    $("sync-dot").className = "dot ok";
    set("platform", ready.ready ? "OPERATIONAL" : "NOT READY");
    set("bus", health.bus); set("auth", health.message_auth ? "ENABLED" : "DISABLED");
    set("connector-status", ready.fragmentation?.configured ? "CONFIGURED" : "NOT CONFIGURED");
    set("ready-tag", ready.ready ? "READY" : "NOT READY");
    set("agents", health.agents); set("roles", ready.roles); set("pending", ready.pending_approvals);
    set("runtime", health.status); set("transport", ready.bus_ok ? "Connected" : "Unavailable");
    set("missing", ready.missing_agents?.length); set("connectors", ready.fragmentation?.connectors);
    set("configured", ready.fragmentation?.configured ? "CONFIGURED" : "DISABLED");
    set("connector-note", ready.fragmentation?.error || "Source connectivity is checked during ingestion, not by this status view.");
  } catch {
    $("sync-dot").className = "dot bad";
    set("sync", "OFFLINE"); set("updated", "Mesh status unavailable");
    for (const id of ["platform","bus","auth","connector-status","agents","roles","pending","runtime","transport","missing","connectors","configured"]) set(id,"—");
    set("ready-tag","UNKNOWN"); set("connector-note","Unable to contact the mesh health service.");
  }
}
refresh(); setInterval(refresh, 5000);
$("public-load").addEventListener("click", async () => {
  const button = $("public-load");
  button.disabled = true;
  set("public-message", "Loading historical records from data.wa.gov…");
  try {
    const response = await fetch("/api/public-data", {cache:"no-store"});
    if (!response.ok) throw new Error("unavailable");
    const data = await response.json();
    set("public-count", data.notification_count);
    set("public-matched", data.notifications_with_details);
    set("public-detail", data.detail_rows);
    set("public-causes", Object.entries(data.causes).map(([name, count]) => `${name}: ${count}`).join(" · "));
    set("public-message", `Fetched ${new Date(data.generated_at).toLocaleString()} · limited sample${data.detail_limit_reached ? " · detail limit reached" : ""}. Historical reports, not live incidents.`);
  } catch {
    for (const id of ["public-count","public-matched","public-detail","public-causes"]) set(id, "—");
    set("public-message", "Public data unavailable. Try again when the publisher is reachable.");
  } finally { button.disabled = false; }
});
