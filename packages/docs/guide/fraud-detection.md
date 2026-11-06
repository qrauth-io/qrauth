# Fraud Detection

QRAuth analyses every scan in the background after the verification response is sent. The `qrauth-scans` worker runs five built-in fraud signals, and the `qrauth-fraud` worker evaluates dynamic rules. Each signal or rule that fires creates a `FraudIncident`. Unresolved incidents and recent scan volume lower the trust score that later verifications of the QR code report (see [Trust Levels](./trust-levels)).

---

## Architecture

```
Scan event ──► verification response (trust score from existing incidents)
    │
    ▼
qrauth-scans worker: 5 built-in signals  ──► FraudIncidents (+ alerts for HIGH/CRITICAL)
    │
    ▼
qrauth-fraud worker: feature vector ──► dynamic rules ──► FraudIncidents
```

---

## Built-in signals

Five signals run in the `qrauth-scans` background worker after each scan, using database queries. IP addresses are stored and compared as SHA-256 hashes.

| Signal | Fires when | Incident type | Severity |
|---|---|---|---|
| Duplicate location | Another organization's QR code is registered within **20 metres** of the scanned code's registered location (potential physical overlay) | `DUPLICATE_LOCATION` | `HIGH` |
| Geo-impossibility | The same hashed IP reported a location more than **500 km** away within the last **30 minutes** | `GEO_IMPOSSIBLE` | `CRITICAL` |
| Scan velocity | The QR code received more than **50 scans** in **5 minutes** | `PATTERN_ANOMALY` | `MEDIUM` |
| Bot user agent | The User-Agent parses as a known bot | `PATTERN_ANOMALY` | `MEDIUM` |
| Device clustering | The same hashed IP scanned **20 or more** distinct QR codes within **1 hour** | `PATTERN_ANOMALY` | `HIGH` |

Incidents from these signals with `HIGH` or `CRITICAL` severity send an alert to the organization.

---

## Dynamic rule engine

Beyond the built-in signals, the platform supports JSON-defined rules stored in the database. After each scan, the `qrauth-fraud` worker computes a feature vector for the scan and evaluates every active and shadow rule against it. Rules are cached for **60 seconds**, so a new or changed rule takes effect within that time. A matching active rule creates a `FraudIncident`; rules do not block a scan.

### Rule status

| Status | Evaluated | Effect of a match |
|---|---|---|
| `ACTIVE` | Yes | Creates a `FraudIncident` that counts toward the trust score and appears in the organization's fraud dashboard |
| `SHADOW` | Yes | Records an internal shadow incident for platform review only: no trust-score effect, not shown to organizations, no alerts |
| `DISABLED` | No | None |

### Rule schema

```json
{
  "name": "Burst from new IPs",
  "conditions": [
    { "field": "scanVelocity5m", "operator": "gt", "value": 30 },
    { "field": "isNewIp", "operator": "eq", "value": true }
  ],
  "action": {
    "type": "PATTERN_ANOMALY",
    "severity": "MEDIUM",
    "reason": "Burst of scans from previously unseen IPs"
  },
  "priority": 100,
  "status": "ACTIVE"
}
```

All conditions must match for the rule to fire.

**Condition operators:** `gt`, `lt`, `gte`, `lte`, `eq`, `neq`, `between`, `in`

**Action:** `type` and `severity` set the created incident's type and severity; `reason` is recorded in the incident details.

### Managing rules

Rules are global and are created by the daily [AI agent](#ai-agent). Platform administrators can list rules, change their status, review what a shadow rule has matched, and promote it:

```
GET   /api/v1/analytics/fraud-rules
PATCH /api/v1/analytics/fraud-rules/:id                  { "status": "ACTIVE" | "SHADOW" | "DISABLED" }
GET   /api/v1/analytics/fraud-rules/:id/shadow-summary   shadow match count, first/last seen, recent samples
POST  /api/v1/analytics/fraud-rules/:id/promote          SHADOW → ACTIVE
POST  /api/v1/analytics/fraud-rules/:id/demote           ACTIVE → SHADOW
```

`PATCH` also accepts `{ "enabled": true | false }`, which maps to `ACTIVE` / `DISABLED`. Status changes are recorded in the audit log.

---

## Feature extraction

The `qrauth-fraud` worker computes these features per scan with Redis counters (expiring after 1 hour or 24 hours). Dynamic rules reference them by name.

| Feature | Description |
|---|---|
| `scanVelocity5m` | Scans of this QR code in the past 5 minutes |
| `scanVelocity1h` | Scans of this QR code in the past hour |
| `ipDispersion1h` | Distinct QR codes scanned from this hashed IP in the past hour |
| `hourOfDay` | UTC hour (0–23) at scan time |
| `dayOfWeek` | UTC day of week (0–6) |
| `isBot` | User-Agent matches a bot/automation pattern |
| `isNewIp` | First scan of this QR code from this hashed IP in the past 24 hours |
| `timeSinceLastScan` | Seconds since the previous scan of this QR code; `999999` when there was none in the past 24 hours |
| `trustScoreTrend` | Average trust score of the last 20 scans of this QR code |

---

## AI agent

A Claude-powered agent runs daily via GitHub Actions. It has access to 8 tools:

| Tool | What it does |
|---|---|
| `query_scan_patterns` | Pull recent scan patterns |
| `query_fraud_incidents` | List FraudIncidents |
| `query_login_events` | Examine login patterns |
| `query_org_activity` | Inspect organization-level activity |
| `query_feature_snapshots` | Read stored feature vectors |
| `create_fraud_rule` | Write a new dynamic fraud rule to the DB |
| `write_report` | Create a daily analysis report |
| `suggest_code_change` | Generate recommendations (human-reviewed) |

Rules created by the agent start in `SHADOW` status. They are evaluated on every scan and record shadow incidents, but do not affect trust scores or organization dashboards until a platform administrator reviews the shadow matches and promotes the rule to `ACTIVE`.

---

## Fraud incidents

When a signal or rule fires, a `FraudIncident` record is created and linked to the scan.

```ts
// GET /api/v1/analytics/fraud
const { data } = await fetch('https://qrauth.io/api/v1/analytics/fraud?resolved=false&severity=HIGH', {
  headers: { Authorization: `Bearer ${apiKey}` },
}).then(r => r.json());

// data[].type, .severity, .details, .resolved, .resolvedAt, .scanId, .qrCode.token
```

**Severity levels:** `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`

Mark an incident resolved:

```ts
// Requires OWNER, ADMIN or MANAGER
await fetch(`https://qrauth.io/api/v1/analytics/fraud/${incidentId}/resolve`, {
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
//   trustScore: 85,
//   transparencyLogVerified: true,
// }
```

For the details of a single incident (type, severity, the signal or rule that fired, and the linked scan), call:

```
GET /api/v1/analytics/fraud/:id
```
