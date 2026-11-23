// Load the real read-only USOC health surface. There is no task-dispatch HTTP
// endpoint; this script must never be pointed at /diagnostics (admin token).
// The bearer token stays in the k6 process environment, never in a browser.
import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter, Trend } from 'k6/metrics';

const readyFailures = new Counter('usoc_ready_failures');
const readinessLatency = new Trend('usoc_readiness_latency_ms');

export const options = {
  stages: [
    { duration: '1m', target: 100 },  // warm-up
    { duration: '3m', target: 500 },  // sustained
    { duration: '2m', target: 1000 }, // HPA scale-out burst
    { duration: '1m', target: 0 },    // cool-down
  ],
  thresholds: {
    http_req_failed: ['rate<0.005'],
    usoc_readiness_latency_ms: ['p(95)<250', 'p(99)<600'],
  },
};

const BASE_URL = __ENV.USOC_BASE_URL || 'http://127.0.0.1:8090';
const HEALTH_TOKEN = __ENV.AGENT_HEALTH_TOKEN || '';

export default function () {
  const headers = { Accept: 'application/json' };
  if (HEALTH_TOKEN) {
    headers.Authorization = `Bearer ${HEALTH_TOKEN}`;
  }

  // Most probes hit /ready; a few hit /health so both liveness and readiness
  // are measured without ever submitting work over HTTP.
  const path = __ITER % 25 === 0 ? '/health' : '/ready';
  const res = http.get(`${BASE_URL}${path}`, { headers });
  readinessLatency.add(res.timings.duration);

  const ok = check(res, {
    'probe status is 200': (r) => r.status === 200,
    'probe body has no topology detail': (r) => {
      if (r.status !== 200) return true;
      const body = r.body || '';
      return !body.includes('agent_id') && !body.includes('topology');
    },
  });
  if (!ok && res.status !== 200) {
    readyFailures.add(1);
  }

  sleep(0.1);
}
