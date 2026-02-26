# Supabase Connect - FastAPI + SQLAlchemy

FastAPI backend for executing read-only SQL queries against a PostgreSQL (Supabase) database. Two endpoints: SQLAlchemy and psycopg2 direct connection.

Live endpoint: [supabase.tigzig.com](https://supabase.tigzig.com)

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/sqlquery_alchemy/` | GET | Execute read-only SQL via SQLAlchemy |
| `/sqlquery_direct/` | GET | Execute read-only SQL via psycopg2 |
| `/health` | GET | Health check |

## Authentication

Bearer token via Authorization header:

```
Authorization: Bearer YOUR_API_KEY
```

## Query Parameter

- `sqlquery` - PostgreSQL-compliant SQL query (read-only, SELECT/SHOW/DESCRIBE/EXPLAIN/WITH only)

## Example

```bash
curl "https://supabase.tigzig.com/sqlquery_alchemy/?sqlquery=SELECT%201%20as%20test" \
  -H "Authorization: Bearer YOUR_API_KEY"
```

## Security Hardening

| # | Layer | What It Does |
|---|-------|-------------|
| 1 | Bearer token auth | All endpoints require `Authorization: Bearer` header with timing-safe comparison (hmac.compare_digest) |
| 2 | Fail-closed auth | If `REX_API_KEY` env var is missing, app refuses to start |
| 3 | SQL prefix allowlist | Only SELECT, SHOW, DESCRIBE, EXPLAIN, WITH queries allowed |
| 4 | SQL keyword blocklist | INSERT, UPDATE, DELETE, DROP, ALTER, CREATE, TRUNCATE, EXEC, COPY, GRANT, REVOKE, and 15+ more blocked |
| 5 | SQL comment rejection | Block `--` and `/*` to prevent comment-based injection bypass |
| 6 | Postgres catalog blocking | pg_catalog, information_schema, pg_stat, pg_shadow, and system functions blocked |
| 7 | Auto-append LIMIT | Queries without an outer LIMIT automatically get LIMIT 1000 |
| 8 | Subquery depth limit | Max 3 SELECT keywords per query (main + 2 subqueries) |
| 9 | ORDER BY validation | Function calls in ORDER BY blocked except whitelisted aggregates |
| 10 | Per-IP rate limiting | 30 requests/minute per IP via SlowAPI, configurable via `RATE_LIMIT` env var |
| 11 | Global rate limiting | 200 requests/minute across all IPs combined, configurable via `GLOBAL_RATE_LIMIT` env var |
| 12 | Per-IP concurrency cap | Max 3 simultaneous in-flight queries per IP, configurable via `MAX_CONCURRENT_PER_IP` |
| 13 | Global concurrency cap | Max 6 simultaneous queries server-wide, configurable via `MAX_CONCURRENT_GLOBAL` |
| 14 | Concurrency leak protection | `asyncio.shield` on counter release prevents permanent lockout from cancelled requests |
| 15 | Read-only sessions | `set_session(readonly=True)` + `SET TRANSACTION READ ONLY` on every connection |
| 16 | Statement timeout | 30-second timeout on psycopg2 direct connections |
| 17 | CORS credentials disabled | `allow_origins=["*"]` with `allow_credentials=False` |
| 18 | Generic error messages | Internal errors return generic messages — no stack traces, file paths, or SQL details leaked |
| 19 | Global exception handler | Catches unhandled exceptions as safety net |
| 20 | Cloudflare IP extraction | Real client IP extracted from `cf-connecting-ip`, `x-forwarded-for` for accurate rate limiting |

## API Monitoring

All requests are logged via [tigzig-api-monitor](https://pypi.org/project/tigzig-api-monitor/), an open-source centralized logging middleware for FastAPI. The middleware captures request metadata including client IP addresses and request bodies for API monitoring and error tracking.

**Data Retention**: The middleware captures data but does not manage its lifecycle. It is the deployer's responsibility to implement appropriate data retention and deletion policies in accordance with their own compliance requirements (GDPR, CCPA, etc.).

**Graceful Degradation**: If the logging service is unavailable, API calls proceed normally — logging fails silently without affecting functionality.

## Configuration

See `.envExample` for all available options:

```env
DATABASE_URL=postgresql://user:password@host:port/dbname
REX_API_KEY=your-api-key-here
RATE_LIMIT=30/minute
GLOBAL_RATE_LIMIT=200/minute
MAX_CONCURRENT_PER_IP=3
MAX_CONCURRENT_GLOBAL=6
MAX_ROWS=1000
```

## Run

```bash
pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 8000
```

## Deployment

Docker container deployed via Coolify (Nixpacks) on Hetzner.

## License

MIT License

## Author

Built by [Amar Harolikar](https://www.linkedin.com/in/amarharolikar/)

Explore 30+ open source AI tools for analytics, databases & automation at [tigzig.com](https://tigzig.com)
