const $ = id => document.getElementById(id);
const set = (id, value) => { const el = $(id); if (el) el.textContent = value ?? "—"; };
const POLL_MS = 5000;
const FETCH_TIMEOUT_MS = 4000;
const RESTRICTED = "NOT EXPOSED";

let inFlight = false;
let pollTimer = null;
let failures = 0;

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

/** Fetch with a bounded timeout so a hung proxy cannot pin the poll loop. */
async function getJson(path, timeoutMs = FETCH_TIMEOUT_MS) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(path, {cache:"no-store", signal:controller.signal});
    if (!response.ok) throw new Error("unavailable");
    return await response.json();
  } finally {
    clearTimeout(timer);
  }
}

async function refresh() {
  if (inFlight) return;
  inFlight = true;
  try {
    const {health, ready} = await getJson("/api/status");
    failures = 0;
    set("sync", "LIVE STATUS");
    set("updated", `Updated ${new Date().toLocaleTimeString()}`);
    $("sync-dot").className = "dot ok";

    const operational = ready?.ready === true;
    set("platform", operational ? "OPERATIONAL" : "NOT READY");
    set("ready-tag", operational ? "READY" : "NOT READY");
    set("runtime", health?.status ?? "UNKNOWN");
    set("transport", ready?.bus_ok === true ? "Connected" : "Unavailable");

    // /health and /ready intentionally publish counts and flags only — agent
    // topology, bus type and connector config stay behind diagnostics auth.
    const running = health?.agents_running;
    const expected = health?.agents_expected;
    set("agents", Number.isFinite(running) && Number.isFinite(expected) ? `${running} / ${expected}` : "—");
    set("roles", RESTRICTED);
    set("bus", RESTRICTED);
    set("auth", health?.message_auth === true ? "ENABLED" : "DISABLED");
    set("pending", ready?.pending_approvals ?? health?.pending_approvals ?? "—");
    set("missing", Number.isFinite(running) && Number.isFinite(expected) ? Math.max(0, expected - running) : "—");
    set("connector-status", RESTRICTED);
    set("configured", RESTRICTED);
    set("connectors", RESTRICTED);
    set("connector-note", "Detailed connector and topology data requires authenticated diagnostics access; it is not published by the health endpoints.");
  } catch {
    failures += 1;
    $("sync-dot").className = "dot bad";
    set("sync", "OFFLINE");
    set("updated", `Status unavailable · retry ${failures}`);
    for (const id of ["platform","bus","auth","connector-status","agents","roles","pending","runtime","transport","missing","connectors","configured"]) set(id,"—");
    set("ready-tag","UNKNOWN");
    set("connector-note","Unable to contact the mesh health service.");
  } finally {
    inFlight = false;
    scheduleNext();
  }
}

function scheduleNext() {
  if (pollTimer) clearTimeout(pollTimer);
  if (document.visibilityState === "hidden") {
    set("sync", "PAUSED");
    return;
  }
  const delay = failures > 0 ? Math.min(POLL_MS * 2 ** Math.min(failures, 3), 60000) : POLL_MS;
  pollTimer = setTimeout(refresh, delay);
}

document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible") { failures = 0; refresh(); }
  else scheduleNext();
});

$("public-load").addEventListener("click", async () => {
  const button = $("public-load");
  button.disabled = true;
  set("public-message", "Loading historical records from data.wa.gov…");
  try {
    const data = await getJson("/api/public-data", 20000);
    set("public-count", data.notification_count);
    set("public-matched", data.notifications_with_details);
    set("public-detail", data.detail_rows);
    set("public-causes", Object.entries(data.causes ?? {}).map(([name, count]) => `${name}: ${count}`).join(" · "));
    set("public-message", `Fetched ${new Date(data.generated_at).toLocaleString()} · limited sample${data.detail_limit_reached ? " · detail limit reached" : ""}. Historical reports, not live incidents.`);
  } catch {
    for (const id of ["public-count","public-matched","public-detail","public-causes"]) set(id, "—");
    set("public-message", "Public data unavailable. Try again when the publisher is reachable.");
  } finally { button.disabled = false; }
});

refresh();
