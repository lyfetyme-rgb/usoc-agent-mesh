const $ = id => document.getElementById(id);
const set = (id, value) => { const el = $(id); if (el) el.textContent = value ?? UNKNOWN; };
const POLL_MS = 5000;
// Keep the browser timeout above the proxy's upstream timeout (8s) so a slow
// probe is reported as a timeout rather than an unexplained abort.
const FETCH_TIMEOUT_MS = 10000;
const UNKNOWN = "UNKNOWN";
const RESTRICTED = "NOT EXPOSED";
const ERROR_LABELS = {
  auth: "AUTH REQUIRED",
  timeout: "TIMED OUT",
  transport: "PROXY OFFLINE",
  invalid_response: "BAD RESPONSE",
  http_500: "PROXY ERROR",
  http_502: "PROXY ERROR",
  http_503: "PUBLISHER UNAVAILABLE",
  http_504: "PUBLISHER TIMEOUT",
};

let inFlight = false;
let pollTimer = null;
let failures = 0;
let paused = false;
let lastGood = null;
let lastGoodAt = null;

function tick() {
  const now = new Date();
  set("clock", now.toLocaleTimeString(undefined, {hour12:false}));
  set("date", now.toLocaleDateString(undefined, {weekday:"short",year:"numeric",month:"short",day:"numeric"}).toUpperCase());
}
tick(); setInterval(tick, 1000);

$("theme").addEventListener("click", () => {
  const light = document.body.classList.toggle("light");
  $("theme-label").textContent = light ? "DARK" : "LIGHT";
  $("theme").setAttribute("aria-pressed", String(light));
});

// An explicit pause control is required for tickers/previews: users must be
// able to stop background work without hiding the tab.
$("live-toggle").addEventListener("click", () => {
  paused = !paused;
  const button = $("live-toggle");
  button.setAttribute("aria-pressed", String(paused));
  $("live-label").textContent = paused ? "RESUME" : "PAUSE";
  if (paused) {
    if (pollTimer) clearTimeout(pollTimer);
    pollTimer = null;
    setSync("PAUSED", "warn");
  } else {
    refresh();
  }
});

$("refresh-now").addEventListener("click", () => {
  if (pollTimer) clearTimeout(pollTimer);
  pollTimer = null;
  refresh();
});

/** Fetch with a bounded timeout so a hung proxy cannot pin the poll loop. */
async function getJson(path, timeoutMs = FETCH_TIMEOUT_MS) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(path, {cache:"no-store", signal:controller.signal});
    if (!response.ok) {
      const error = new Error("unavailable");
      error.status = response.status;
      throw error;
    }
    return await response.json();
  } catch (error) {
    if (error && error.name === "AbortError") {
      const timeout = new Error("timeout");
      timeout.reason = "timeout";
      throw timeout;
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

function reasonLabel(reason) {
  if (ERROR_LABELS[reason]) return ERROR_LABELS[reason];
  if (typeof reason === "string" && reason.startsWith("http_")) return `HTTP ${reason.slice(5)}`;
  return UNKNOWN;
}

function firstError(errors) {
  if (!errors) return null;
  return errors.health || errors.ready || null;
}

function setSync(text, kind) {
  set("sync", text);
  const label = $("sync");
  if (label) label.className = kind;
  $("sync-dot").className = `dot ${kind}`;
}

function applyValues(data) {
  const health = data?.health ?? null;
  const ready = data?.ready ?? null;
  const running = health?.agents_running;
  const expected = health?.agents_expected;
  const countsKnown = Number.isFinite(running) && Number.isFinite(expected);
  const readyKnown = typeof ready?.ready === "boolean";
  const authKnown = typeof health?.message_auth === "boolean";
  const busKnown = typeof ready?.bus_ok === "boolean";

  set("platform", readyKnown ? (ready.ready ? "OPERATIONAL" : "NOT READY") : UNKNOWN);
  set("ready-tag", readyKnown ? (ready.ready ? "READY" : "NOT READY") : UNKNOWN);
  set("runtime", health?.status ?? UNKNOWN);
  set("transport", busKnown ? (ready.bus_ok ? "Connected" : "Unavailable") : UNKNOWN);
  set("agents", countsKnown ? `${running} / ${expected}` : UNKNOWN);
  set("roles", RESTRICTED);
  set("bus", RESTRICTED);
  set("auth", authKnown ? (health.message_auth ? "ENABLED" : "DISABLED") : UNKNOWN);
  const pending = ready?.pending_approvals ?? health?.pending_approvals;
  set("pending", Number.isFinite(pending) ? pending : UNKNOWN);
  set("missing", countsKnown ? Math.max(0, expected - running) : UNKNOWN);
  set("connector-status", RESTRICTED);
  set("configured", RESTRICTED);
  set("connectors", RESTRICTED);
  set("connector-note", "Detailed connector and topology data requires authenticated diagnostics access; it is not published by the health endpoints.");
  const bengal = health?.bengal;
  const bengalOn = bengal?.enabled === true;
  set("bengal-method", bengalOn ? (bengal.method_version ?? UNKNOWN) : RESTRICTED);
  set("bengal-modes", bengalOn && Array.isArray(bengal.modes) ? bengal.modes.length : RESTRICTED);
  set("bengal-protocol", bengalOn ? (bengal.protocol_version ?? UNKNOWN) : RESTRICTED);
}

function rememberGood(data) {
  lastGood = {health: data?.health ?? null, ready: data?.ready ?? null};
  lastGoodAt = new Date();
}

function timestamp(date) {
  return date.toLocaleTimeString(undefined, {hour12:false});
}

function markFailure(reason) {
  failures += 1;
  if (lastGood) {
    applyValues(lastGood);
    setSync(`STALE · ${reasonLabel(reason)}`, "warn");
    set("updated", `Last good ${timestamp(lastGoodAt)} · retry ${failures}`);
    set("ready-tag", "STALE");
    return;
  }
  setSync(`OFFLINE · ${reasonLabel(reason)}`, "bad");
  set("updated", `Status unavailable · retry ${failures}`);
  for (const id of ["platform","bus","auth","connector-status","agents","roles","pending","runtime","transport","missing","connectors","configured","bengal-method","bengal-modes","bengal-protocol"]) set(id, UNKNOWN);
  set("ready-tag", UNKNOWN);
  set("connector-note", "Unable to contact the mesh health service.");
}

async function refresh() {
  if (inFlight) return;
  inFlight = true;
  try {
    const data = await getJson("/api/status");
    applyValues(data);
    const error = firstError(data.errors);
    if (error) {
      setSync(`PARTIAL · ${reasonLabel(error)}`, "warn");
      set("updated", `Partial status ${timestamp(new Date())}`);
    } else {
      rememberGood(data);
      failures = 0;
      setSync("LIVE STATUS", "ok");
      set("updated", `Updated ${timestamp(new Date())}`);
    }
  } catch (error) {
    const reason = error?.reason || (error?.status ? `http_${error.status}` : "transport");
    markFailure(reason);
  } finally {
    inFlight = false;
    scheduleNext();
  }
}

function scheduleNext() {
  if (pollTimer) clearTimeout(pollTimer);
  pollTimer = null;
  // Explicit user pause and hidden tabs both stop background work. Neither
  // clears `failures`, so a returning tab never bursts through its backoff.
  if (paused || document.visibilityState === "hidden") {
    setSync("PAUSED", "warn");
    return;
  }
  const delay = failures > 0 ? Math.min(POLL_MS * 2 ** Math.min(failures, 3), 60000) : POLL_MS;
  pollTimer = setTimeout(refresh, delay);
}

document.addEventListener("visibilitychange", () => {
  if (paused) return;
  if (document.visibilityState === "visible") {
    if (pollTimer) clearTimeout(pollTimer);
    refresh();
  } else {
    scheduleNext();
  }
});

const publicPanel = $("public-panel");
$("public-load").addEventListener("click", async () => {
  const button = $("public-load");
  button.disabled = true;
  publicPanel.setAttribute("aria-busy", "true");
  set("public-message", "Loading historical records from data.wa.gov…");
  try {
    const data = await getJson("/api/public-data", 30000);
    set("public-count", data.notification_count);
    set("public-matched", data.notifications_with_details);
    set("public-detail", data.detail_rows);
    set("public-causes", Object.entries(data.causes ?? {}).map(([name, count]) => `${name}: ${count}`).join(" · "));
    set("public-message", `Fetched ${new Date(data.generated_at).toLocaleString()} · limited sample${data.detail_limit_reached ? " · detail limit reached" : ""}. Historical reports, not live incidents.`);
  } catch (error) {
    for (const id of ["public-count","public-matched","public-detail","public-causes"]) set(id, UNKNOWN);
    const reason = error?.status ? reasonLabel(`http_${error.status}`) : reasonLabel(error?.reason);
    set("public-message", `Public data unavailable (${reason}). Try again when the publisher is reachable.`);
  } finally {
    button.disabled = false;
    publicPanel.setAttribute("aria-busy", "false");
  }
});

refresh();
