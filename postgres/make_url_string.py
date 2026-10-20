#!/usr/bin/env python3
"""
make_db_url.py - Build a URL-safe SQLAlchemy/PostgreSQL connection string.

Percent-encodes username, password and database name so characters like
@ : / ? # % [ ] are safe inside a URL. Standard library only, no deps.

Password input (in order of precedence):
  1. --password-stdin   read from stdin (for pipes / CI)
  2. $DB_PASSWORD       environment variable
  3. interactive prompt (hidden, not stored in shell history)

Examples:
  ./make_db_url.py -u dummyuser -H mydb.xxxx.rds.amazonaws.com -d defaultdb
  ./make_db_url.py -u dummyuser -H pgdb -p 9003 -d defaultdb --env
  printf '%s' "$PW" | ./make_db_url.py -u app -H pgdb -d appdb --password-stdin
"""

import argparse
import getpass
import os
import sys
from urllib.parse import quote, unquote, urlsplit


def build_url(driver: str, user: str, password: str, host: str,
              port: int, database: str | None) -> str:
    enc_user = quote(user, safe="")
    enc_pass = quote(password, safe="")
    # Bracket bare IPv6 literals
    host_part = f"[{host}]" if ":" in host and not host.startswith("[") else host
    url = f"{driver}://{enc_user}:{enc_pass}@{host_part}:{port}"
    if database:
        url += "/" + quote(database, safe="")
    return url


def verify(url: str, user: str, password: str, host: str, port: int) -> None:
    """Round-trip parse to make sure the URL decodes back to the inputs."""
    p = urlsplit(url)
    checks = {
        "username": (unquote(p.username or ""), user),
        "password": (unquote(p.password or ""), password),
        "host": (p.hostname, host.strip("[]").lower()),
        "port": (p.port, port),
    }
    bad = [k for k, (got, exp) in checks.items() if got != exp]
    if bad:
        sys.exit(f"[ERROR] Round-trip check failed for: {', '.join(bad)}")


def mask(url: str) -> str:
    p = urlsplit(url)
    if p.password is None:
        return url
    return url.replace(f":{p.password}@", ":***@", 1)


def main() -> None:
    ap = argparse.ArgumentParser(description="Build a URL-safe DB connection string.")
    ap.add_argument("-u", "--user", required=True)
    ap.add_argument("-H", "--host", required=True)
    ap.add_argument("-p", "--port", type=int, default=5432)
    ap.add_argument("-d", "--database", help="database name (omitted from URL if not set)")
    ap.add_argument("--driver", default="postgresql+psycopg",
                    help="SQLAlchemy dialect+driver (default: postgresql+psycopg)")
    ap.add_argument("--password-stdin", action="store_true",
                    help="read password from stdin instead of prompting")
    ap.add_argument("--env", action="store_true",
                    help="print as a .env line: DATABASE_URL='...'")
    ap.add_argument("--masked", action="store_true",
                    help="print with password masked (for logs / sanity check)")
    args = ap.parse_args()

    if args.password_stdin:
        password = sys.stdin.read().rstrip("\r\n")
    elif os.getenv("DB_PASSWORD"):
        password = os.environ["DB_PASSWORD"]
    else:
        password = getpass.getpass("Password: ")

    if not password:
        sys.exit("[ERROR] Empty password")
    if not args.database:
        print("[WARN] No --database given; URL will have no database path.", file=sys.stderr)

    url = build_url(args.driver, args.user, password, args.host, args.port, args.database)
    verify(url, args.user, password, args.host, args.port)

    out = mask(url) if args.masked else url
    print(f"DATABASE_URL='{out}'" if args.env else out)


if __name__ == "__main__":
    main()
