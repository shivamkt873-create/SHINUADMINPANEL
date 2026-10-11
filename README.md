# SHINU ADMIN PANEL — secure starter

This is a small, independent license-management service for software you own or are authorized to manage. It includes a web dashboard, server-side admin authentication, PostgreSQL persistence, key generation, expiry, deactivate/reactivate, and a public validation endpoint.

## Included
- Admin login using a bcrypt password hash and an HttpOnly, SameSite=Strict session cookie.
- Random 160-bit license keys. Only a SHA-256 hash is stored in PostgreSQL; the full key is shown once at generation.
- 1/7/30/90/365-day or custom expiry.
- Deactivate/reactivate and list licenses.
- Public `POST /api/license/validate` endpoint.
- Rate limiting, Helmet security headers, parameterized SQL, environment-based secrets.

## Important limitation
This is an independent license service. It does **not** modify or connect to the previously uploaded Quotex extension, and keys from this service will not automatically work in that extension. Do not use it to enable fake balances, fabricated trades, or misleading trading records. Integrate only with software you own or are authorized to manage.

## Deploy free-tier starter (availability/limits can change)
1. Create a PostgreSQL project at https://supabase.com/ and copy its connection string (use the pooler or direct connection as supported by your plan; require SSL).
2. Create a GitHub repository and upload the contents of this folder.
3. Create a Render Web Service at https://render.com/ from that repository. Render can read `render.yaml`; alternatively set build command `npm install` and start command `npm start`.
4. In Render Environment, set:
   - `DATABASE_URL`: Supabase PostgreSQL connection string.
   - `ADMIN_USERNAME`: your chosen admin username.
   - `ADMIN_PASSWORD_HASH`: generate as described below.
   - `JWT_SECRET`: a unique random value of at least 32 characters. Use Render's Generate Value option if available.
   - `NODE_ENV=production`.
5. Generate the bcrypt hash on your computer:
   - Install Node.js 20+.
   - Run `npm install`.
   - Run `npm run hash-password`, enter a strong password (12+ characters), and copy the printed hash into `ADMIN_PASSWORD_HASH` on Render.
   - Never put your plain password or JWT secret in GitHub.
6. Deploy. Open your Render service URL. The dashboard is served at `/`.

Render free web services may sleep when idle and free database availability/limits can change. For production or important licenses, use a paid always-on service and regular database backups.

## API contract
`POST /api/license/validate`
```json
{"key":"SHINU-ABCDE-..."}
```
Valid response:
```json
{"valid":true,"expiresAt":"..."}
```
Invalid response:
```json
{"valid":false,"reason":"not_found"}
```

Admin endpoints require the HttpOnly session cookie:
- `POST /api/admin/login` `{ "username": "...", "password": "..." }`
- `POST /api/admin/logout`
- `GET /api/admin/me`
- `GET /api/admin/licenses`
- `POST /api/admin/licenses` `{ "label":"optional", "days":30 }` or `{ "label":"optional", "expiresAt":"2030-01-01T23:59:59Z" }`
- `PATCH /api/admin/licenses/:id` `{ "active": false }`

## Security notes
- Keep `DATABASE_URL`, `ADMIN_PASSWORD_HASH`, and `JWT_SECRET` private.
- Do not expose database credentials or admin tokens in a browser extension.
- Use HTTPS (Render provides HTTPS for deployed services).
- Rotate the admin password hash and JWT secret if compromised.
- This starter has one administrator configured through environment variables; it does not include public signup or multiple admin accounts.
