# SIP API Plugin

Generic JSON API v1 for SIP automation and the `sipctl` CLI.

## Routes

All routes are under `/api/v1` and return a standard JSON envelope:

```json
{"ok": true, "data": {}, "error": null, "meta": {"api_version": "v1"}}
```

## Authentication

The API supports existing SIP session cookies and v1 bearer tokens:

```http
Authorization: Bearer sip_xxx
```

Token management:

- `GET /api/v1/auth/tokens`
- `POST /api/v1/auth/tokens` with `action=create`
- `POST /api/v1/auth/tokens` with `action=revoke`

Raw tokens are returned only once and stored hashed server-side.

## OpenAPI

OpenAPI JSON is available at:

```text
/api/v1/openapi.json
```
