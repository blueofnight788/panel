# Railway Config Panel

Management dashboard (Node + Express, JSON storage). It does NOT run Xray itself:
it talks to the API of a 3x-ui (Sanaei) panel running on your own VPS.

## Railway setup
1. Push this folder to a GitHub repo and deploy it on Railway.
2. Add a Volume, mount path `/data`.
3. Variables: `ADMIN_PASSWORD` (required), `DATA_DIR=/data`, optional `SESSION_SECRET`.
4. Domain: Railway sets `RAILWAY_PUBLIC_DOMAIN` automatically once you generate/add a domain; the panel picks it up and uses it for subscription links (`https://your-domain/sub/<id>`). You can also override it in the panel (Servers tab) or via `PANEL_DOMAIN`.
5. Open the Railway domain, log in, add your 3x-ui server (URL with webBasePath), then create configs.

Local run: `ADMIN_PASSWORD=test npm install && npm start`
