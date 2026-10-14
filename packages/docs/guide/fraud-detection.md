# Fraud Detection

QRAuth runs a multi-layer fraud detection pipeline on every scan. Trust score starts at 100 and drops as signals fire. The final score gates the verification page reveal, determines alert routing, and is available in the API response.

---

## Architecture

```
Scan event
    │
    ▼
6 inline signals  ──► trust score deductions
    │
    ▼
Dynamic rule engine  ──► additional deductions / custom actions
    │
    ▼
Adaptive scoring  ──► per-org weight adjustments
    │
    ▼
Final trust score (0–100)
```

---

## Inline signals

Six signals run synchronously on every scan, with no external calls. They complete in <5ms combined via Redis-backed counters.

### 1. Duplicate location (`DUPLICATE_LOCATION`)

**Deduction: −30**

Fires when another organization's QR code is registered within **20 metres** of the scanned code's registered location. Indicates potential physical overlay attack (placing a fraudulent code on top of a legitimate one).

### 2. Proxy detected (`PROXY_DETECTED`)

**Deduction: −25**

Fires when the client IP matches the IP reputation database for known proxies, VPNs, and Tor exit nodes. Intended scans from proxied corporate networks may trigger this — use the dashboard to whitelist IP ranges.

### 3. Geo-impossibility (`GEO_IMPOSSIBLE`)

**Deduction: −40**

Fires when the same device (by IP hash) scanned a QR more than **500km away** within the last **30 minutes**. No commercial aircraft cruises fast enough for this to be legitimate.

### 4. Velocity spike (`VELOCITY`)

**Deduction: −20**

Fires when more than the configured threshold of scans arrive from the same IP within a 60-second window. Tunable per org in the dashboard under **Fraud → Velocity Threshold**.

### 5. Bot signature (`BOT`)

**Deduction: −35**

Fires on headless browser indicators: missing or spoofed User-Agent, absent WebGL/canvas fingerprint, rapid sequential scans with identical headers, or known bot user-agent patterns.

### 6. Device clustering (`DEVICE_CLUSTERING`)

**Deduction: −15**

Fires when more than N distinct device fingerprints arrive from the same IP in a short window — indicative of a coordinated scanning farm.

---

## Dynamic rule engine

Beyond the six inline signals, the platform supports JSON-defined rules stored in the database. Rules are evaluated on every scan and take effect within **60 seconds** of being created or updated.

### Rule schema

```json
{
  "id": "rule_abc123",
  "name": "Greece parking meter burst",
  "condition": {
    "field": "metadata.contentType",
    "operator": "eq",
    "value": "parking"
  },
  "action": {
    "type": "deduct",
    "amount": 30
  },
  "enabled": true
}
```

**Condition operators:** `eq`, `neq`, `gt`, `lt`, `contains`, `regex`

**Action types:** `deduct` (reduce trust score), `flag` (create FraudIncident), `block` (reject scan entirely)

### Create a rule via API

```
POST /api/v1/fraud/rules
```

::: code-group

```ts [Node.js]
const rule = await fetch('https://qrauth.io/api/v1/fraud/rules', {
  method: 'POST',
  headers: {
    Authorization: `Bearer ${apiKey}`,
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    name: 'High-value transaction extra check',
    condition: { field: 'metadata.amount', operator: 'gt', value: 500 },
    action: { type: 'flag' },
  }),
}).then(r => r.json());
```

```python [Python]
import httpx

resp = httpx.post(
    "https://qrauth.io/api/v1/fraud/rules",
    headers={"Authorization": f"Bearer {api_key}"},
    json={
        "name": "High-value transaction extra check",
        "condition": {"field": "metadata.amount", "operator": "gt", "value": 500},
        "action": {"type": "flag"},
    },
)
rule = resp.json()
```

:::

---

## Feature extraction

The feature extraction service computes per-scan signals that rules and the AI agent can reference. Features are stored in Redis with a 7-day TTL.

| Feature | Description |
|---|---|
| `scan_velocity_1m` | Scans from this IP in the past 60 seconds |
| `scan_velocity_24h` | Scans from this IP in the past 24 hours |
| `device_count_24h` | Distinct device fingerprints from this IP today |
| `geo_distance_30m` | Max distance (km) between last two scans from this device |
| `hour_of_day` | Local hour (0–23) at scan time |
| `is_weekend` | Boolean |
| `ua_risk_score` | 0–1 from User-Agent analysis |

---

## Adaptive scoring

Adaptive scoring adjusts per-signal deduction weights based on your organization's historical scan profile. For example, if your QR codes are intentionally deployed in a proxy-heavy corporate environment, the system automatically learns that `PROXY_DETECTED` is less predictive of real fraud for your account and reduces its weight.

Weights are recalculated daily using a rolling 30-day scan window. The adaptive weights are visible in the dashboard under **Fraud → Adaptive Weights**.

::: info
Adaptive scoring requires a minimum of 500 scans in the past 30 days to activate. Below this threshold, default weights apply.
:::

---

## AI agent

A Claude-powered agent runs daily via GitHub Actions. It has access to 8 tools:

| Tool | What it does |
|---|---|
| `query_scans` | Pull recent scan data with fraud signal breakdown |
| `query_fraud` | List active FraudIncidents with severity filter |
| `query_logins` | Examine auth session patterns |
| `query_orgs` | Inspect organization-level anomalies |
| `query_features` | Read feature extraction data from Redis |
| `create_rule` | Write a new dynamic fraud rule to the DB |
| `write_report` | Create a daily analysis report |
| `suggest_changes` | Generate recommendations (human-reviewed) |

Rules created by the agent go live immediately. Reports are posted to the `#fraud-alerts` Slack channel and stored in **Dashboard → Agent Runs**.

---

## Fraud incidents

When a signal fires above the configured threshold, a `FraudIncident` record is created and linked to the scan.

```ts
// GET /api/v1/fraud/incidents
const { data } = await fetch('https://qrauth.io/api/v1/fraud/incidents?resolved=false&severity=HIGH', {
  headers: { Authorization: `Bearer ${apiKey}` },
}).then(r => r.json());

// data[].type, .severity, .details, .resolvedAt, .scan.id
```

**Severity levels:** `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`

Mark an incident resolved:

```ts
await fetch(`https://qrauth.io/api/v1/fraud/incidents/${incidentId}/resolve`, {
  method: 'POST',
  headers: { Authorization: `Bearer ${apiKey}` },
});
```

---

## Score summary in the verify response

```ts
const result = await qrauth.verify('AbCdEfGh');

result.security;
// {
//   signatureValid: true,
//   proxyDetected: false,
//   trustScore: 85,
//   transparencyLogVerified: true,
// }
```

For fine-grained signal breakdown, call the internal scan endpoint:

```
GET /api/v1/scans/:scanId/fraud-details
```

This returns the full deduction ledger, fired signals, and matched dynamic rules for that specific scan.
