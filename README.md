# Google Analytics 4 MCP Server

A [Model Context Protocol](https://modelcontextprotocol.io) server for GA4 — lets Claude read and write your Google Analytics data via the GA4 Data API and Admin API.

## Available Tools

| Tool | API | Description |
|------|-----|-------------|
| `run_report` | Data API (read) | Fetch traffic, conversions, top pages, any GA4 metric |
| `get_account_summaries` | Admin API (read) | List all GA4 accounts and properties |
| `add_referral_exclusion` | Admin API (write) | Block self-referral domains (e.g. PayPal, Stripe) |
| `create_conversion_event` | Admin API (write) | Mark GA4 events as conversions |
| `create_audience` | Admin API (write) | Create remarketing audiences |
| `update_property_settings` | Admin API (write) | Change property name, timezone, currency |

---

## Setup

### 1. Google Cloud Console

1. Go to [console.cloud.google.com](https://console.cloud.google.com)
2. Create a project (or select existing)
3. Enable these APIs:
   - **Google Analytics Data API**
   - **Google Analytics Admin API**
4. Go to **APIs & Services → Credentials → Create Credentials → OAuth 2.0 Client ID**
5. Application type: **Web application**
6. Add authorized redirect URI: `https://your-app.onrender.com/oauth/callback`
7. Copy **Client ID** and **Client Secret**

### 2. Deploy to Render

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy)

Or manually:

1. Push this repo to GitHub
2. In [Render](https://render.com), click **New → Web Service**
3. Connect your GitHub repo
4. Set environment variables (see below)
5. Deploy

**Required Environment Variables in Render:**

| Variable | Value |
|----------|-------|
| `GOOGLE_CLIENT_ID` | From Google Cloud Console |
| `GOOGLE_CLIENT_SECRET` | From Google Cloud Console |
| `SECRET_KEY` | Random string (Render can auto-generate) |
| `BASE_URL` | Your Render URL: `https://your-app.onrender.com` |
| `TOKEN_STORAGE_DIR` | `/tmp/ga_tokens` (or persistent disk path) |

> **Note:** `/tmp` is ephemeral on Render's free tier — tokens are lost on restart. For production, add a [Render Disk](https://render.com/docs/disks) and set `TOKEN_STORAGE_DIR` to the mount path.

### 3. Authenticate

Visit `https://your-app.onrender.com/oauth/login?user_id=yourname` and complete the Google OAuth flow. You'll receive an API key.

Multiple users can authenticate by using different `user_id` values.

---

## Configure Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS):

```json
{
  "mcpServers": {
    "google-analytics": {
      "type": "http",
      "url": "https://your-app.onrender.com/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_API_KEY"
      }
    }
  }
}
```

---

## Usage Examples

Once connected to Claude, you can say:

- *"Show me the top 10 pages by sessions for property 123456789 in the last 30 days"*
- *"List all my GA4 properties"*
- *"Add PayPal as a referral exclusion for property 123456789"*
- *"Create a conversion event for 'form_submit' on property 123456789"*
- *"Create an audience of users who purchased in the last 30 days"*
- *"Update property 123456789 to use Europe/Berlin timezone and EUR currency"*

All tool calls require `user_id` matching the ID you used when authenticating.

---

## Local Development

```bash
# Clone and install
git clone https://github.com/your-username/google-analytics-mcp
cd google-analytics-mcp
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Configure
cp .env.example .env
# Edit .env with your Google credentials and BASE_URL=http://localhost:8000

# Run
python main.py
```

Visit `http://localhost:8000` to start.

---

## OAuth Scopes

The server requests these Google OAuth scopes:

- `https://www.googleapis.com/auth/analytics.readonly` — read GA4 data
- `https://www.googleapis.com/auth/analytics.edit` — write GA4 admin settings
- `https://www.googleapis.com/auth/analytics` — full access

---

## Architecture

```
┌─────────────────────────────────────┐
│         FastAPI Application         │
│                                     │
│  /              → Landing page      │
│  /oauth/login   → Start OAuth flow  │
│  /oauth/callback → Save tokens      │
│  /status        → Authenticated users│
│  /mcp           → MCP HTTP endpoint │
└─────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────┐
│         Token Storage               │
│  {TOKEN_STORAGE_DIR}/<user_id>.json │
│  {TOKEN_STORAGE_DIR}/_api_keys.json │
└─────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────┐
│      Google APIs                    │
│  GA4 Data API (read)                │
│  GA4 Admin API (read + write)       │
└─────────────────────────────────────┘
```

## Security Notes

- API keys are stored in `_api_keys.json` — protect this file
- Tokens are user-scoped; each user only accesses their own GA4 data
- Use HTTPS in production (Render provides this automatically)
- Set `ALLOWED_EMAILS` env var to restrict which Google accounts can authenticate
