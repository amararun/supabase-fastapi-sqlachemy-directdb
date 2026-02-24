# Supabase Connect - FastAPI + SQLAlchemy

FastAPI app for executing read-only PostgreSQL queries against a Supabase database.

## Endpoints

- `GET /sqlquery_alchemy/` - Execute SQL via SQLAlchemy (recommended)
- `GET /sqlquery_direct/` - Execute SQL via direct psycopg2 connection

## Authentication

Bearer token via Authorization header:

```
Authorization: Bearer YOUR_API_KEY
```

## Query Parameter

- `sqlquery` - PostgreSQL-compliant SQL query (read-only, SELECT only)

## Example

```bash
curl "https://supabase.tigzig.com/sqlquery_alchemy/?sqlquery=SELECT%201" \
  -H "Authorization: Bearer YOUR_API_KEY"
```

## Security

- Bearer token authentication (API key via Authorization header)
- Read-only database sessions enforced at connection level
- Read-only transactions enforced per query
- Rate limiting via SlowAPI
- CORS middleware
- API monitoring via tigzig_api_monitor

## Environment Variables

- `DATABASE_URL` - PostgreSQL connection string
- `REX_API_KEY` - API key for Bearer authentication
- `RATE_LIMIT` - Rate limit (default: 100/hour)

## Deployment

Deployed via Coolify on Hetzner. Push to `main` to deploy.
