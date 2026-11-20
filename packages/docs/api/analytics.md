# Scan Analytics

Scan counts for an organization's QR codes: daily or weekly series, breakdowns by place and device, per-code analytics, and a CSV export.

## What is recorded

When a code is scanned, QRAuth records the scan's time and, from the request:

- **place**: country, region and city, looked up from the scanner's IP address in a local database before the address is hashed. The address itself is not stored or sent anywhere. IP geolocation by [DB-IP](https://db-ip.com).
- **device**: device type (`mobile`, `tablet`, `desktop`, `tv` or `bot`), operating system and browser, from the user agent.

Scans recorded before place recording was introduced (November 2026) have no place; they count in totals and appear as `unknown` in place breakdowns. Their device fields were filled in from the stored user agent.

**Unique scans** are distinct (keyed, hashed) IP addresses per code per UTC day. People behind a shared address (an office, a mobile carrier) count once, and a phone that changes address counts again. An organization's or a week's unique count is the sum of the daily per-code values.

Days are UTC. Ranges cover at most the last 365 days: after 365 days a scan's hashed address, user agent, region and city are removed.

## Plans

| | Free | Pro, Business, Enterprise |
|---|---|---|
| Summary counts (`GET /api/v1/analytics/summary`), including the last 7 days' daily totals | yes | yes |
| Time series, breakdowns, per-code analytics, CSV export | no | yes |

On the Free plan the endpoints below answer `403` with `"code": "analytics-plan-required"`.

## Common parameters

**Headers:** `X-API-Key: <key>`

| Param | Type | Description |
|-------|------|-------------|
| `from` | `YYYY-MM-DD` | First day (UTC), at most 364 days before today. Default: 29 days before `to` |
| `to` | `YYYY-MM-DD` | Last day (UTC), not in the future. Default: today |
| `token` | string | Limit to one of the organization's QR codes |

An invalid range is `400`; a `token` that is not one of the organization's codes is `404`.

---

## Time Series

`GET /api/v1/analytics/timeseries`

| Param | Type | Description |
|-------|------|-------------|
| `granularity` | `day` \| `week` | Default `day`. Weeks start on Monday; partial weeks at the ends of the range are included |

**Response (200):**

```json
{
  "granularity": "day",
  "from": "2026-10-03",
  "to": "2026-11-01",
  "total": 1840,
  "unique": 1312,
  "points": [
    { "date": "2026-10-03", "total": 52, "unique": 40 },
    { "date": "2026-10-04", "total": 61, "unique": 47 }
  ]
}
```

Every day (or week) of the range is present, with zeros where there were no scans.

---

## Breakdown

`GET /api/v1/analytics/breakdown`

| Param | Type | Description |
|-------|------|-------------|
| `dimension` | `country` \| `city` \| `deviceType` \| `os` \| `browser` | Required |

**Response (200):**

```json
{
  "from": "2026-10-03",
  "to": "2026-11-01",
  "dimension": "country",
  "total": 1840,
  "items": [
    { "key": "GR", "count": 1502 },
    { "key": "DE", "count": 201 },
    { "key": "unknown", "count": 137 }
  ],
  "other": 0
}
```

Countries are ISO 3166-1 alpha-2 codes. City keys are `CC|City` (for example `GR|Thessaloniki`). Values missing on a scan count as `unknown`. At most 50 items are returned, largest first; `other` is the sum of the rest.

---

## Per-Code Analytics

`GET /api/v1/analytics/qrcodes/:token`

Takes `from`, `to` and `granularity`. Returns the code, its time series and its country, device type, OS and browser breakdowns (10 items each).

**Response (200):**

```json
{
  "qrCode": { "token": "aB3dE5gH", "label": "Parking Zone A" },
  "granularity": "day",
  "from": "2026-10-03",
  "to": "2026-11-01",
  "total": 412,
  "unique": 301,
  "points": [{ "date": "2026-10-03", "total": 12, "unique": 9 }],
  "breakdowns": {
    "country": { "total": 412, "items": [{ "key": "GR", "count": 398 }], "other": 0 },
    "deviceType": { "total": 412, "items": [{ "key": "mobile", "count": 377 }], "other": 0 },
    "os": { "total": 412, "items": [{ "key": "iOS", "count": 220 }], "other": 0 },
    "browser": { "total": 412, "items": [{ "key": "Safari", "count": 205 }], "other": 0 }
  }
}
```

---

## CSV Export

`GET /api/v1/analytics/export.csv`

Takes `from`, `to` and `token`. Returns every scan in the range, oldest first, as `text/csv` (UTF-8, CRLF line ends), streamed as an attachment:

```
scanned_at,code,label,country,region,city,device_type,os,browser,trust_score
2026-11-01T09:14:03.112Z,aB3dE5gH,Parking Zone A,GR,Central Macedonia,Thessaloniki,mobile,iOS,Safari,100
```

The export contains no IP address, hashed address or user agent. Cells that a spreadsheet would read as a formula (starting with `=`, `+`, `-` or `@`) are prefixed with `'`.
