from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from tigzig_api_monitor import APIMonitorMiddleware
from sqlalchemy import create_engine, text, event
from sqlalchemy.exc import SQLAlchemyError
import logging
import os
from typing import Any, Union
from starlette.middleware.base import BaseHTTPMiddleware
import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Database URL and credentials
DATABASE_URL = os.getenv("DATABASE_URL")
REX_API_KEY = os.getenv("REX_API_KEY")

if not DATABASE_URL:
    logger.error("DATABASE_URL environment variable is not set")
    raise ValueError("DATABASE_URL environment variable is required")

if not REX_API_KEY:
    logger.error("REX_API_KEY environment variable is not set")
    raise ValueError("REX_API_KEY environment variable is required")

# Parse connection details from DATABASE_URL
from urllib.parse import urlparse
parsed_url = urlparse(DATABASE_URL)
DB_HOST = parsed_url.hostname
DB_PORT = parsed_url.port
DB_NAME = parsed_url.path[1:]  # Remove leading slash
DB_USER = parsed_url.username
DB_PASSWORD = parsed_url.password

# Initialize FastAPI
app = FastAPI()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Update with your frontend origins in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add centralized API monitoring middleware
# v1.3.1 - CF-Connecting-IP fix for accurate GeoIP behind Cloudflare
app.add_middleware(
    APIMonitorMiddleware,
    app_name="SUPABASE_CONNECT_FASTAPI",
    include_prefixes=("/sqlquery_alchemy/", "/sqlquery_direct/"),  # Specific endpoints only
)

# Rate limiting configuration (default 100/hour)
RATE_LIMIT = os.getenv("RATE_LIMIT", "100/hour")
logger.info(f"Using rate limit: {RATE_LIMIT}")

# Initialize SlowAPI limiter
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

# Custom 429 handler (match prior app behavior)
async def custom_rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={"detail": "Rate limit exceeded. Please try again later or contact your administrator."}
    )

app.add_exception_handler(RateLimitExceeded, custom_rate_limit_exceeded_handler)

# Create SQLAlchemy engine
engine = create_engine(DATABASE_URL, pool_pre_ping=True)

# Ensure all SQLAlchemy connections are session-level read-only
@event.listens_for(engine, "connect")
def set_session_readonly(dbapi_connection, connection_record):
    try:
        # dbapi_connection is the raw psycopg2 connection
        dbapi_connection.set_session(readonly=True, autocommit=False)
        logger.debug("SQLAlchemy DBAPI session set to readonly")
    except Exception as e:
        logger.warning(f"Failed to set SQLAlchemy session to readonly: {e}")

@app.get("/sqlquery_alchemy/")
@limiter.limit(RATE_LIMIT)
async def sqlquery_alchemy(sqlquery: str, request: Request) -> Any:
    """Execute SQL query using SQLAlchemy and return results directly."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer ") or auth_header[7:] != REX_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    logger.debug(f"Received API call to SQLAlchemy endpoint: {request.url}")
    logger.debug(f"SQL Query: {sqlquery}")

    try:
        with engine.connect() as connection:
            # Start a read-only transaction to enforce read-only at the DB level
            trans = connection.begin()
            try:
                connection.exec_driver_sql("SET TRANSACTION READ ONLY")

                # Execute query
                result = connection.execute(text(sqlquery))
                
                # If SELECT query, return results
                if sqlquery.strip().lower().startswith('select'):
                    # Get column names
                    columns = result.keys()
                    
                    # Fetch all rows
                    rows = result.fetchall()
                    
                    # Convert rows to list of dictionaries
                    results = [dict(zip(columns, row)) for row in rows]
                    
                    logger.debug(f"Query executed successfully via SQLAlchemy, returned {len(results)} rows")
                    trans.commit()
                    return results
                
                # For non-SELECT queries, attempt will fail due to read-only transaction
                else:
                    trans.commit()
                    logger.debug("Non-SELECT query attempted in read-only transaction")
                    return {"status": "success", "message": "Query executed successfully"}
            except:
                trans.rollback()
                raise

    except SQLAlchemyError as e:
        logger.error(f"SQLAlchemy error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error in SQLAlchemy endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")

@app.get("/sqlquery_direct/")
@limiter.limit(RATE_LIMIT)
async def sqlquery_direct(sqlquery: str, request: Request) -> Any:
    """Execute SQL query using direct psycopg2 connection and return results."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer ") or auth_header[7:] != REX_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    logger.debug(f"Received API call to direct connection endpoint: {request.url}")
    logger.debug(f"SQL Query: {sqlquery}")

    connection = None
    try:
        # Create direct connection
        connection = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
            cursor_factory=RealDictCursor  # This will return results as dictionaries
        )
        # Enforce read-only at the session level for this connection
        connection.set_session(readonly=True, autocommit=False)
        
        with connection.cursor() as cursor:
            # Execute query
            cursor.execute(sqlquery)
            
            # If SELECT query, return results
            if sqlquery.strip().lower().startswith('select'):
                results = cursor.fetchall()
                logger.debug(f"Query executed successfully via direct connection, returned {len(results)} rows")
                # RealDictCursor returns results as dictionaries, so we can return directly
                return list(results)
            
            # For non-SELECT queries, commit and return status
            else:
                connection.commit()
                logger.debug("Non-SELECT query executed successfully via direct connection")
                return {"status": "success", "message": "Query executed successfully"}

    except psycopg2.Error as e:
        logger.error(f"PostgreSQL error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error in direct connection endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")
    finally:
        if connection:
            connection.close()
            logger.debug("Database connection closed")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
