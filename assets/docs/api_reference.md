# Call Spoofing — API Calling Documentation Summary

## Base URL
```
https://api.callspoofing.org/v1
```

## Authentication
Header on every request (key prefix `vac_live_`):
```
X-API-Key: vac_live_YOUR_KEY
```
or
```
Authorization: Bearer vac_live_YOUR_KEY
```
Keys created in panel: Setting → API → API Calling → Create key.

## Prerequisites
- An active SIP user with a password in the panel (SIP Users)
- An API Calling key with `calls:write` scope (and `calls:read` to poll status)
- Balance on the account

---

## POST /calls — Place a single call

```
POST https://api.callspoofing.org/v1/calls
```

### Request Body

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `to` | **yes** | string (phone number or `sandbox:<robot>`, max 70 chars) | Who to call. Digits with optional `+`; spaces/dashes removed. |
| `from` | no | string (phone number, max 32 chars) | **Caller ID to display.** Default: the default caller ID in API Calling settings, else SIP user's own. |
| `flow` | yes (unless `flow_id`) | list of steps (or one step) | What happens when the call is answered. |
| `flow_id` | no | `flow_…` id | A saved flow to run instead of inline `flow`. Wins when both sent. |
| `webhook_url` | no | URL (max 500 chars) | Where call events go. Default: webhook in API Calling settings. |
| `events` | no | list (max 30) | Only these events go to webhook, e.g. `["call.ended", "dtmf.*"]`. Empty = all. |
| `metadata` | no | object (max 4000 chars) | Your own fields (order id, customer id…). Sent back on every event. |
| `variables` | no | object (max 4000 chars) | Values for `{name}` placeholders in `say` steps. |
| `sip_user` | no | string | Which SIP user places the call. Default: one in API Calling settings. |
| `ring_timeout` | no | 5-120 (default 45) | Seconds phone may ring before `no_answer`. |
| `max_duration` | no | 10-14400 (default 3600) | Call ended after this many seconds. Max 3600. |
| `record` | no | bool (default false) | Record the whole call, both sides. |
| `Idempotency-Key` | no (header) | string (max 80 chars) | Prevent duplicate calls. |

### Example Request
```json
{
  "to": "+18005551234",
  "from": "+18005550199",
  "flow": [
    {"pause": 3},
    {"say": "Hello, this is a message from our company."}
  ]
}
```

### Response (201 Created)
```json
{
  "id": "call_8k2m4q7w1z9x3c5v6b0n",
  "direction": "outbound",
  "to": "+18005551234",
  "from": "+18005550199",
  "status": "queued",
  ...
}
```

---

## POST /batches — Bulk call (multiple numbers)

```
POST https://api.callspoofing.org/v1/batches
```

### Request Body

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `numbers` | **yes** | list of 1-10,000 | Phone numbers as strings, or objects `{"to", "variables", "metadata"}` per number. |
| `name` | no | string (max 120 chars) | A name for your own use. |
| `flow` | yes (unless `flow_id`) | list of steps | What happens when a call is answered. |
| `flow_id` | no | `flow_…` id | Saved flow to run instead. |
| `from` | no | string (max 32 chars) | **Caller ID.** Default: API Calling settings default. |
| `sip_user` | no | string | SIP user that places the calls. |
| `calls_at_once` | no | 1-200 (default 5) | Concurrent calls. |
| `ring_timeout` | no | 5-120 (default 45) | Ring timeout per call. |
| `max_duration` | no | 10-14400 (default 3600) | Max call duration. |
| `record` | no | bool (default false) | Record each call. |
| `webhook_url` | no | URL | Where events go. |
| `events` | no | list (max 30) | Event filter. |
| `metadata` | no | object | Shared metadata; per-number metadata merges over it. |
| `variables` | no | object | Shared variables; per-number variables win. |

### Example Request
```json
{
  "name": "Lead outreach",
  "numbers": [
    "+18005550100",
    {"to": "+18005550101", "variables": {"name": "Alice"}},
    "+18005550102"
  ],
  "from": "+18005550199",
  "flow": [
    {"pause": 3},
    {"say": {"text": "Hello {name}, this is our message.", "voice": "edge:en-US-AriaNeural"}}
  ],
  "calls_at_once": 5
}
```

---

## Flow Steps (relevant ones)

### `say` — Text-to-speech
```json
{"say": "Hello"}
```
Full form:
```json
{
  "say": {
    "text": "Hello {name}, your code is {code}.",
    "voice": "edge:en-US-AriaNeural",
    "language": "en",
    "loop": 1,
    "speed": 1.0
  }
}
```
- `text`: required, max 3000 chars. `{name}` placeholders filled from call's `variables`.
- `voice`: a voice id from `GET /voices` — Cartesia id or `edge:<ShortName>`. Default: language's default.
- `language`: language code, up to 8 chars.
- `loop`: 1-10, how many times to repeat.
- `speed`: 0.5-2.0 (default 1.0), Edge voices only.
- 322 free Microsoft Edge voices available (e.g., `edge:en-US-AriaNeural`).

### `play` — Play audio file
```json
{"play": "aud_5t7y2u9i4o1p6a3s8d0f"}
```
Full form:
```json
{
  "play": {
    "audio": "https://example.com/sounds/hold.mp3",
    "loop": 2
  }
}
```
- `audio`: required. An `aud_…` id (uploaded via `POST /audio`) or an HTTP(S) URL (max 500 chars). URL is fetched once and converted to 8 kHz.
- `loop`: 1-10.

### `pause` — Silent wait
```json
{"pause": 2}
```
Full form:
```json
{"pause": {"seconds": 2}}
```
- `seconds`: required, 1-60. How long to wait in silence.

### `gather` — Collect DTMF keypress
```json
{"gather": true}
```
Full form:
```json
{
  "gather": {
    "digits": 4,
    "timeout": 8,
    "inter_digit_timeout": 4,
    "finish_on_key": "#",
    "attempts": 3,
    "name": "pin",
    "prompt": [{"say": "Please enter your code"}]
  }
}
```

---

## Other Useful Endpoints

| Method | Path | Scope | Description |
|--------|------|-------|-------------|
| `GET` | `/calls` | `calls:read` | List calls (filter by status, batch_id, direction, date range) |
| `GET` | `/calls/{call_id}` | `calls:read` | Get one call with recordings and flow |
| `GET` | `/calls/{call_id}/events` | `calls:read` | Events of a call |
| `POST` | `/calls/{call_id}/flow` | `calls:write` | Change a running call's flow |
| `POST` | `/calls/{call_id}/hangup` | `calls:write` | Hang up a call |
| `GET` | `/batches/{batch_id}` | `calls:read` | Get a bulk call status |
| `POST` | `/batches/{batch_id}/pause` | `calls:write` | Pause a bulk call |
| `POST` | `/batches/{batch_id}/resume` | `calls:write` | Resume a bulk call |
| `POST` | `/batches/{batch_id}/cancel` | `calls:write` | Cancel a bulk call |
| `GET` | `/voices` | `account:read` | List available TTS voices |
| `POST` | `/voices/sample` | `account:read` | Preview a voice |
| `POST` | `/audio` | `media:write` | Upload audio file |
| `GET` | `/account` | `account:read` | Account info and balance |
| `POST` | `/flows` | `flows:write` | Save a reusable flow |
| `POST` | `/flows/validate` | (no scope) | Validate a flow without saving |
| `POST` | `/webhooks/test` | `calls:write` | Test webhook delivery |

---

## Webhook Events
Set `webhook_url` on the call or in API Calling settings. Events include:
- `call.answered`, `call.ended`
- `dtmf.received`, `gather.timeout`
- `recording.ready`
- `batch.*` events for bulk calls

---

## Rate Limits
Per-key limits (minute, hour, day). Headers: `X-RateLimit-Remaining-Minute`, `-Hour`, `-Day`. 429 includes `Retry-After`.

## Sandbox Testing
Free sandbox robots for testing: `sandbox:press1`, etc. No billing, never leaves server.

## Pagination
`GET` list endpoints use `limit` (1-100, default 20) and `starting_after` (last id of previous page). Response includes `has_more`.

## IDs
Prefixed: `call_`, `bat_`, `flow_`, `aud_`, `rec_`, `evt_`, `agr_` + 20 alphanumeric chars.
