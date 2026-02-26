"""
Supabase Connect FastAPI - Read-only SQL query API for PostgreSQL (Supabase)
Two endpoints: SQLAlchemy and psycopg2 direct connection
"""

import asyncio
import hmac
import logging
import os
import re
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from sqlalchemy import create_engine, text, event
from sqlalchemy.exc import SQLAlchemyError

try:
    from tigzig_api_monitor import APIMonitorMiddleware
    HAS_LOGGER = True
except ImportError:
    HAS_LOGGER = False

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("supabase-connect")

DATABASE_URL = os.getenv("DATABASE_URL")
REX_API_KEY = os.getenv("REX_API_KEY")

if not DATABASE_URL:
    raise RuntimeError("FATAL: DATABASE_URL not set. Refusing to start.")
if not REX_API_KEY:
    raise RuntimeError("FATAL: REX_API_KEY not set. Refusing to start.")

# Parse connection details for psycopg2 direct endpoint
parsed_url = urlparse(DATABASE_URL)
DB_HOST = parsed_url.hostname
DB_PORT = parsed_url.port
DB_NAME = parsed_url.path[1:]
DB_USER = parsed_url.username
DB_PASSWORD = parsed_url.password

# Rate limiting and concurrency (all configurable via env vars)
RATE_LIMIT = os.getenv("RATE_LIMIT", "30/minute")
GLOBAL_RATE_LIMIT = os.getenv("GLOBAL_RATE_LIMIT", "200/minute")
MAX_CONCURRENT_PER_IP = int(os.getenv("MAX_CONCURRENT_PER_IP", "3"))
MAX_CONCURRENT_GLOBAL = int(os.getenv("MAX_CONCURRENT_GLOBAL", "6"))
MAX_ROWS = int(os.getenv("MAX_ROWS", "1000"))

logger.info(f"Rate limit: {RATE_LIMIT} | Global: {GLOBAL_RATE_LIMIT} | Concurrency: {MAX_CONCURRENT_PER_IP}/IP, {MAX_CONCURRENT_GLOBAL} global")

# ---------------------------------------------------------------------------
# Client IP extraction (Cloudflare-aware)
# ---------------------------------------------------------------------------
def get_client_ip(request: Request) -> str:
    for header in ("x-original-client-ip", "cf-connecting-ip", "x-forwarded-for", "x-real-ip"):
        val = request.headers.get(header)
        if val:
            return val.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

# ---------------------------------------------------------------------------
# Auth helper (timing-safe)
# ---------------------------------------------------------------------------
def verify_bearer_auth(request: Request):
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    token = auth_header[7:]
    if not hmac.compare_digest(token, REX_API_KEY):
        raise HTTPException(status_code=403, detail="Invalid API key")

# ---------------------------------------------------------------------------
# Concurrency tracking (per-IP + global with asyncio.shield)
# ---------------------------------------------------------------------------
_active_queries: Dict[str, int] = {}
_active_queries_lock = asyncio.Lock()
_global_active = 0
_global_active_lock = asyncio.Lock()


async def check_concurrency(client_ip: str):
    global _global_active
    async with _global_active_lock:
        if _global_active >= MAX_CONCURRENT_GLOBAL:
            logger.info(f"Concurrency DENIED (global cap {MAX_CONCURRENT_GLOBAL}) for {client_ip}")
            raise HTTPException(status_code=503, detail="Server busy. Please try again later.")
        _global_active += 1
    async with _active_queries_lock:
        current = _active_queries.get(client_ip, 0)
        if current >= MAX_CONCURRENT_PER_IP:
            async with _global_active_lock:
                _global_active -= 1
            logger.info(f"Concurrency DENIED (per-IP cap {MAX_CONCURRENT_PER_IP}) for {client_ip}")
            raise HTTPException(status_code=429, detail="Too many concurrent requests.")
        _active_queries[client_ip] = current + 1
    logger.info(f"Concurrency ACQUIRED for {client_ip} | ip={current + 1}, global={_global_active}")


async def release_concurrency(client_ip: str):
    try:
        await asyncio.shield(_release_concurrency_inner(client_ip))
    except asyncio.CancelledError:
        pass


async def _release_concurrency_inner(client_ip: str):
    global _global_active
    async with _active_queries_lock:
        current = _active_queries.get(client_ip, 0)
        if current <= 1:
            _active_queries.pop(client_ip, None)
        else:
            _active_queries[client_ip] = current - 1
    async with _global_active_lock:
        _global_active = max(0, _global_active - 1)
    logger.info(f"Concurrency RELEASED for {client_ip} | ip={max(0, current - 1)}, global={_global_active}")


# ---------------------------------------------------------------------------
# SQL Validation (read-only enforcement at application level)
# ---------------------------------------------------------------------------
BLOCKED_KEYWORDS = [
    "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE", "TRUNCATE",
    "EXEC", "EXECUTE", "COPY", "GRANT", "REVOKE", "SET", "COMMIT",
    "ROLLBACK", "SAVEPOINT", "LOCK", "VACUUM", "REINDEX", "DISCARD",
    "GENERATE_SERIES", "RANGE", "UNNEST", "STRING_TO_TABLE", "REGEXP_SPLIT_TO_TABLE",
]

ALLOWED_PREFIXES = ("SELECT", "SHOW", "DESCRIBE", "EXPLAIN", "WITH")

BLOCKED_PG_SOURCES = [
    "PG_SHADOW", "PG_AUTHID", "PG_ROLES", "PG_USER", "PG_GROUP",
    "PG_STAT_ACTIVITY", "PG_STAT_REPLICATION", "PG_STAT_SSL",
    "PG_SETTINGS", "PG_HBA_FILE_RULES", "PG_CONFIG",
    "INFORMATION_SCHEMA",
    "PG_TABLES", "PG_CLASS", "PG_CATALOG", "PG_EXTENSION",
    "PG_NAMESPACE", "PG_ATTRIBUTE", "PG_INDEX", "PG_CONSTRAINT",
    "INET_SERVER_ADDR", "INET_SERVER_PORT",
    "INET_CLIENT_ADDR", "INET_CLIENT_PORT",
    "CURRENT_SETTING", "PG_READ_FILE", "PG_LS_DIR",
    "PG_STAT_FILE", "PG_READ_BINARY_FILE",
    "VERSION()", "CURRENT_USER", "CURRENT_DATABASE",
]

_ORDER_BY_ALLOWED_FUNCTIONS = {
    "SUM", "COUNT", "AVG", "MIN", "MAX", "COALESCE", "NULLIF", "CASE",
}


def validate_sql(sql: str) -> Optional[str]:
    """Validate SQL is read-only. Returns error message or None if OK."""
    stripped = sql.strip()
    if not stripped:
        return "Empty query"
    if "/*" in stripped or "--" in stripped:
        return "SQL comments are not allowed"
    upper = stripped.upper()
    if not any(upper.startswith(p) for p in ALLOWED_PREFIXES):
        return "Only SELECT/SHOW/DESCRIBE/EXPLAIN/WITH queries allowed"
    for kw in BLOCKED_KEYWORDS:
        if f" {kw} " in f" {upper} " or f" {kw}(" in f" {upper}(" or upper.startswith(kw):
            return f"Blocked keyword: {kw}"
    for src in BLOCKED_PG_SOURCES:
        if src in upper:
            return "Access to system catalogs is not allowed"
    select_count = len(re.findall(r'\bSELECT\b', upper))
    if select_count > 3:
        return "Query too complex (too many subqueries)"
    order_by_error = _validate_order_by(upper)
    if order_by_error:
        return order_by_error
    return None


def _validate_order_by(upper_sql: str) -> Optional[str]:
    orig_match = re.search(r'\bORDER\s+BY\b(.+?)(?:\bLIMIT\b|\bOFFSET\b|\bFETCH\b|\bFOR\b|\bUNION\b|$)', upper_sql, re.DOTALL)
    if orig_match and re.search(r'\bSELECT\b', orig_match.group(1)):
        return "Subqueries in ORDER BY are not allowed"
    depth = 0
    outer_chars = []
    for ch in upper_sql:
        if ch == '(':
            depth += 1
            if depth == 1:
                outer_chars.append(ch)
            continue
        elif ch == ')':
            if depth == 1:
                outer_chars.append(ch)
            depth = max(0, depth - 1)
            continue
        if depth == 0:
            outer_chars.append(ch)
    outer_sql = ''.join(outer_chars)
    match = re.search(r'\bORDER\s+BY\b(.+?)(?:\bLIMIT\b|\bOFFSET\b|\bFETCH\b|\bFOR\b|\bUNION\b|$)', outer_sql, re.DOTALL)
    if not match:
        return None
    order_clause = match.group(1)
    func_calls = re.findall(r'\b([A-Z_][A-Z0-9_]*)\s*\(', order_clause)
    for func_name in func_calls:
        if func_name not in _ORDER_BY_ALLOWED_FUNCTIONS:
            return f"Function calls in ORDER BY are not allowed (found: {func_name})"
    return None


def ensure_limit(sql: str, max_rows: int) -> str:
    """Auto-append LIMIT if query doesn't have one at outer level."""
    stripped = sql.strip().rstrip(";")
    upper = stripped.upper()
    if not (upper.startswith("SELECT") or upper.startswith("WITH")):
        return sql
    depth = 0
    outer_chars = []
    for ch in stripped:
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth = max(0, depth - 1)
        if depth == 0:
            outer_chars.append(ch)
    outer_sql = ''.join(outer_chars).upper()
    if "LIMIT" not in outer_sql:
        return f"{stripped} LIMIT {max_rows}"
    return sql


# ---------------------------------------------------------------------------
# FastAPI App
# ---------------------------------------------------------------------------
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

if HAS_LOGGER:
    app.add_middleware(
        APIMonitorMiddleware,
        app_name="SUPABASE_CONNECT_FASTAPI",
        include_prefixes=("/sqlquery_alchemy/", "/sqlquery_direct/"),
    )

# Rate limiting with Cloudflare-aware IP extraction
limiter = Limiter(key_func=get_client_ip)
app.state.limiter = limiter


async def custom_rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={"detail": "Rate limit exceeded. Please try again later."}
    )

app.add_exception_handler(RateLimitExceeded, custom_rate_limit_exceeded_handler)


# Global exception handler (safety net)
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled error on {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


# SQLAlchemy engine (read-only enforced at session level)
engine = create_engine(DATABASE_URL, pool_pre_ping=True)


@event.listens_for(engine, "connect")
def set_session_readonly(dbapi_connection, connection_record):
    try:
        dbapi_connection.set_session(readonly=True, autocommit=False)
    except Exception as e:
        logger.warning(f"Failed to set SQLAlchemy session to readonly: {e}")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.get("/sqlquery_alchemy/")
@limiter.limit(RATE_LIMIT)
@limiter.shared_limit(GLOBAL_RATE_LIMIT, scope="global_query", key_func=lambda *args, **kwargs: "global")
async def sqlquery_alchemy(sqlquery: str, request: Request) -> Any:
    """Execute read-only SQL query using SQLAlchemy."""
    verify_bearer_auth(request)
    client_ip = get_client_ip(request)

    # Validate SQL
    error = validate_sql(sqlquery)
    if error:
        logger.warning(f"SQL validation rejected from {client_ip}: {error}")
        raise HTTPException(status_code=400, detail=error)

    # Auto-append LIMIT
    sqlquery = ensure_limit(sqlquery, MAX_ROWS)

    await check_concurrency(client_ip)
    try:
        with engine.connect() as connection:
            trans = connection.begin()
            try:
                connection.exec_driver_sql("SET TRANSACTION READ ONLY")
                result = connection.execute(text(sqlquery))

                if sqlquery.strip().lower().startswith('select') or sqlquery.strip().lower().startswith('with'):
                    columns = result.keys()
                    rows = result.fetchall()
                    results = [dict(zip(columns, row)) for row in rows]
                    trans.commit()
                    return results
                else:
                    trans.commit()
                    return {"status": "success", "message": "Query executed successfully"}
            except:
                trans.rollback()
                raise

    except HTTPException:
        raise
    except SQLAlchemyError as e:
        logger.error(f"SQLAlchemy error from {client_ip}: {e}")
        raise HTTPException(status_code=500, detail="Database query failed")
    except Exception as e:
        logger.error(f"Unexpected error in SQLAlchemy endpoint from {client_ip}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        await release_concurrency(client_ip)


@app.get("/sqlquery_direct/")
@limiter.limit(RATE_LIMIT)
@limiter.shared_limit(GLOBAL_RATE_LIMIT, scope="global_query", key_func=lambda *args, **kwargs: "global")
async def sqlquery_direct(sqlquery: str, request: Request) -> Any:
    """Execute read-only SQL query using direct psycopg2 connection."""
    verify_bearer_auth(request)
    client_ip = get_client_ip(request)

    # Validate SQL
    error = validate_sql(sqlquery)
    if error:
        logger.warning(f"SQL validation rejected from {client_ip}: {error}")
        raise HTTPException(status_code=400, detail=error)

    # Auto-append LIMIT
    sqlquery = ensure_limit(sqlquery, MAX_ROWS)

    await check_concurrency(client_ip)
    connection = None
    try:
        connection = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
            cursor_factory=RealDictCursor,
            connect_timeout=10,
            options="-c statement_timeout=30000"
        )
        connection.set_session(readonly=True, autocommit=False)

        with connection.cursor() as cursor:
            cursor.execute(sqlquery)

            if sqlquery.strip().lower().startswith('select') or sqlquery.strip().lower().startswith('with'):
                results = cursor.fetchall()
                return list(results)
            else:
                connection.commit()
                return {"status": "success", "message": "Query executed successfully"}

    except HTTPException:
        raise
    except psycopg2.Error as e:
        logger.error(f"PostgreSQL error from {client_ip}: {e}")
        raise HTTPException(status_code=500, detail="Database query failed")
    except Exception as e:
        logger.error(f"Unexpected error in direct endpoint from {client_ip}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        if connection:
            connection.close()
        await release_concurrency(client_ip)


@app.get("/health")
async def health():
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
