# TGVPANEL Reseller API (initial scope)

The reseller API is a separate, HMAC-authenticated namespace at `/api/v1/reseller/`. It uses actual TGVPANEL records and the existing KVM/LXC `InstanceManager`. The customer directory is a reseller-owned CRM contact registry, not a TGVPANEL login or customer-to-VPS relationship; it grants no access to compute or other resources. Customer status is descriptive only. Notes are encrypted at rest with the existing TGVPANEL AES-256-GCM vault; do not use them as a credential store. Plans, quotas, invoices, payments, and reseller IP allocations are not implemented. An admin creates a user with role `reseller`; resellers are not staff and cannot list shared/other users' instances.

## Reseller key lifecycle (browser session, CSRF-protected)

- `GET /api/v1/reseller/api-keys` — list own key metadata (never secrets).
- `POST /api/v1/reseller/api-keys` — create a credential pair; API key and secret are returned once.
- `GET /api/v1/reseller/api-keys/:id` — inspect own metadata.
- `PUT /api/v1/reseller/api-keys/:id` — update name, description, permissions, exact IP allowlist, expiration or requests/minute.
- `POST /api/v1/reseller/api-keys/:id/rotate` — rotate the key ID and secret together; old pair immediately stops working; new pair returned once.
- `POST /api/v1/reseller/api-keys/:id/disable` / `.../enable` — immediately toggle access.
- `DELETE /api/v1/reseller/api-keys/:id` — revoke own key.
- `GET /api/v1/reseller/api-keys/:id/usage?limit=50&offset=0` — recent request summary and logs.

Each reseller can have at most 20 active keys. Key secrets have 256 bits of entropy; the key ID hash and secret hash are stored, and the HMAC secret is encrypted with TGVPANEL's existing AES-256-GCM secret vault to verify requests. The raw secret is never returned by listing or admin APIs. Use TLS, store credentials in a secret manager, and never place them in source control or URLs.

## HMAC signing format

Required headers:

- `X-TGV-API-KEY`: full `tgvpk_…` key identifier.
- `X-TGV-TIMESTAMP`: Unix time in seconds (10 decimal digits).
- `X-TGV-NONCE`: fresh random value, 16–128 URL-safe characters. A nonce can be used once per key.
- `X-TGV-SIGNATURE`: lowercase hex HMAC-SHA256.

Construct exactly these UTF-8 canonical fields separated by line-feed (`\n`), with no trailing newline:

```text
<timestamp>
<nonce>
<uppercase HTTP method>
<exact path and query as sent, including /api/v1 prefix>
<lowercase hex SHA-256 of the exact raw HTTP body bytes; empty body hashes as SHA256(empty)>
```

Then compute `hex(HMAC-SHA256(apiSecret, canonicalBytes))`. For JSON requests, sign the exact serialized bytes you send; the server verifies the raw body, not a reserialized object. Timestamp skew is limited to 300 seconds. Replay attempts are rejected using unique SQLite nonce records. Per-key rate limits are 1–6000 requests per minute. IP allowlists accept exact IPv4/IPv6 addresses only (no CIDR or wildcard).

## Node.js example

```js
import crypto from 'node:crypto';

async function tgvRequest({ apiKey, apiSecret, method = 'GET', path, body }) {
  const timestamp = String(Math.floor(Date.now() / 1000));
  const nonce = crypto.randomBytes(16).toString('hex');
  const rawBody = body === undefined ? '' : JSON.stringify(body);
  const bodyHash = crypto.createHash('sha256').update(rawBody, 'utf8').digest('hex');
  const canonical = `${timestamp}\n${nonce}\n${method.toUpperCase()}\n${path}\n${bodyHash}`;
  const signature = crypto.createHmac('sha256', apiSecret).update(canonical, 'utf8').digest('hex');
  const response = await fetch(`https://panel.example${path}`, {
    method,
    headers: {
      'X-TGV-API-KEY': apiKey,
      'X-TGV-TIMESTAMP': timestamp,
      'X-TGV-NONCE': nonce,
      'X-TGV-SIGNATURE': signature,
      ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
    },
    ...(body === undefined ? {} : { body: rawBody }),
  });
  return { status: response.status, data: await response.json() };
}

const result = await tgvRequest({
  apiKey: process.env.TGV_API_KEY,
  apiSecret: process.env.TGV_API_SECRET,
  path: '/api/v1/reseller/vps',
});
```

## Python example

```python
import hashlib, hmac, os, secrets, time, requests

api_key = os.environ['TGV_API_KEY']
api_secret = os.environ['TGV_API_SECRET'].encode()
path = '/api/v1/reseller/stats'
timestamp = str(int(time.time()))
nonce = secrets.token_hex(16)
body = b''
body_hash = hashlib.sha256(body).hexdigest()
canonical = f'{timestamp}\n{nonce}\nGET\n{path}\n{body_hash}'.encode()
signature = hmac.new(api_secret, canonical, hashlib.sha256).hexdigest()
response = requests.get('https://panel.example' + path, headers={
    'X-TGV-API-KEY': api_key,
    'X-TGV-TIMESTAMP': timestamp,
    'X-TGV-NONCE': nonce,
    'X-TGV-SIGNATURE': signature,
}, timeout=20)
response.raise_for_status()
print(response.json())
```

## cURL example (GET)

```sh
API_KEY="$TGV_API_KEY"
API_SECRET="$TGV_API_SECRET"
PATH_QUERY='/api/v1/reseller/stats'
TS="$(date +%s)"
NONCE="$(openssl rand -hex 16)"
BODY_HASH="$(printf '' | sha256sum | cut -d' ' -f1)"
CANONICAL="$(printf '%s\n%s\nGET\n%s\n%s' "$TS" "$NONCE" "$PATH_QUERY" "$BODY_HASH")"
SIGNATURE="$(printf '%s' "$CANONICAL" | openssl dgst -sha256 -hmac "$API_SECRET" | awk '{print $NF}')"
curl --fail-with-body --get "https://panel.example${PATH_QUERY}" \
  -H "X-TGV-API-KEY: ${API_KEY}" \
  -H "X-TGV-TIMESTAMP: ${TS}" \
  -H "X-TGV-NONCE: ${NONCE}" \
  -H "X-TGV-SIGNATURE: ${SIGNATURE}"
```

## Data API and scopes

- `GET /api/v1/reseller/customers?limit=50&offset=0&status=active&search=...` — list only this reseller's CRM contact records (`customers.read`). Limit is 1–100 and offset 0–1,000,000.
- `POST /api/v1/reseller/customers` (`customers.create`) — create a contact with display name and email; optional external reference, notes, and status.
- `GET /api/v1/reseller/customers/:id` (`customers.read`) — read only the reseller's own contact record.
- `PUT /api/v1/reseller/customers/:id` (`customers.update`) — partially update name, email, external reference, notes, or active/suspended status.
- `DELETE /api/v1/reseller/customers/:id` (`customers.delete`) — permanently delete the CRM contact record; audit logs retain only the action and record ID, not contact fields.
- `GET /api/v1/reseller/vps?limit=50&offset=0&engine=kvm|lxc&status=running&search=...` — only VPS records owned by the authenticated reseller (`vps.read`). `limit` is 1–100 (default 50), `offset` is 0–1,000,000, `status` is at most 32 letters/underscores/hyphens, and `search` is at most 100 characters; response includes `pagination { limit, offset, total }`.
- `GET /api/v1/reseller/vps/:id?engine=kvm|lxc` — owner-only detail (`vps.read`).
- `POST /api/v1/reseller/vps/:id/{start|stop|restart}?engine=kvm|lxc` — existing lifecycle service, owner check and matching `vps.start`, `vps.stop` or `vps.restart` scope.
- `GET /api/v1/reseller/stats` — counts and allocated CPU/RAM/disk computed from owned records (`stats.read`).
- `GET /api/v1/reseller/resources` — owned allocated totals plus aggregated real telemetry where available (`resources.read`). Missing live telemetry is returned as `null`; `limitsAvailable` is explicitly false because reseller quota/allocation models do not exist yet.
- `GET /api/v1/reseller/resources/usage` — per-instance owned allocations and real adapter telemetry where available (`resources.read`; telemetry can be `null` when a real provider cannot report it).

Only the scopes listed above are currently accepted when creating a key. The supported customer scopes operate only on reseller-owned CRM contacts. Scopes such as `vps.create`, `vps.reinstall`, `vps.delete`, `plans.read`, `ips.read`, and `transactions.read` are not currently exposed or accepted; they will be added only alongside real backend operations and tests.

## Admin oversight

- `GET /api/v1/reseller/admin/accounts` (`admin` role) lists reseller account metadata and resource usage aggregated from VPS records owned by each account.
- `POST /api/v1/reseller/admin/accounts/:id/suspend` immediately disables the reseller account and all its API keys/nonces; suspension is audited.
- `POST /api/v1/reseller/admin/accounts/:id/unsuspend` restores account login, but keys remain disabled until explicitly re-enabled by an authorized user/admin workflow.
- `GET /api/v1/reseller/admin/api-keys` (`admin` role) lists key metadata only.
- `POST /api/v1/reseller/admin/api-keys/:id/disable` immediately disables a key.
- `DELETE /api/v1/reseller/admin/api-keys/:id` revokes it.
- Admin UI: **Admin → API Keys & Webhooks → Reseller HMAC API Keys**.

HMAC requests are logged with key/user identity (where known), method, path (no query/body), source IP, status and success/failure. Sensitive lifecycle changes are written to the existing activity audit. Key/secret material is excluded from logs and administrator views.
