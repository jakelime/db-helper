# helpers/postgres.py
# DB Helper updated for PostgreSQL
"""PostgreSQL helper script to interact with PostgreSQL databases.
- Creates databases and users with specific roles.
- Manages permissions including default privileges for future tables.
- Provides a structure similar to the MongoDB helper for consistency.
"""

import argparse
import logging
import subprocess
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Self
from urllib.parse import unquote, urlparse

import psycopg
import tomlkit
from psycopg import sql

# --- Basic Configuration Setup ---
def setup_basic_stream_logging():
    logging.basicConfig(
        format="%(levelname)s:%(name)s: %(message)s",
        level=logging.INFO,
        stream=sys.stdout,
    )

setup_basic_stream_logging()
lg = logging.getLogger("pg_helper")
CONFIG_FILE = Path(__file__).parent / "secrets.postgres.toml"

# Default configuration mirroring the requirements
DEFAULT_CONFIG = {
    "core": {
        "POSTGRES_URI": "postgresql://rootuser:Th8pdKayocQwAQKTK2@localhost:5432/postgres",
        "DOCKER_CONTAINER": "jfc_pgdb2",
    },
    "admin": {
        "user": "db_admin",
        "password": "ChangeMeAdmin123",
        # db_admin gets CREATEDB and access to all managed databases
    },
    "databases": [
        {
            "db_name": "db1",
            "users": [
                {
                    "user": "db1_owner",
                    "password": "ChangeMeOwner123",
                    "role": "owner",
                },
                {
                    "user": "app_user1",
                    "password": "ChangeMeApp1_123",
                    "role": "read_write_create", # rw + update + delete + table creation
                },
                {
                    "user": "app_user2",
                    "password": "ChangeMeApp2_123",
                    "role": "read_write", # rw + update (no create table)
                },
                {
                    "user": "read_user",
                    "password": "ChangeMeRead123",
                    "role": "read_only", # r
                },
            ],
        },
    ],
}


class ConfigHelper:
    default_config: dict = DEFAULT_CONFIG
    config: dict = {}

    def __init__(self, filepath: Path = CONFIG_FILE):
        self.filepath = filepath
        if not filepath.exists():
            lg.info("Configuration file not found.")
            lg.info("Writing default configuration..")
            self.write_config(self.default_config)

        # Load config, fallback to default if it fails
        loaded_config = self.load_config()
        self.config = (
            loaded_config if loaded_config is not None else self.default_config
        )

    def load_config(self) -> dict | None:
        try:
            with open(self.filepath, "r", encoding="utf-8") as f:
                config = tomlkit.load(f)
            lg.debug("Configuration loaded successfully.")
            return config
        except Exception as e:
            lg.error(f"File read error in {self.filepath}: {e}")
            lg.warning("Using default configuration...")
            return None

    def write_config(self, config: dict) -> None:
        try:
            with open(self.filepath, "w", encoding="utf-8") as f:
                tomlkit.dump(config, f)
            lg.info("Configuration written successfully.")
        except Exception as e:
            lg.error(f"Error writing configuration file: {e}")
            raise e

    def validate_config(self) -> Self:
        cfg = self.config
        try:
            _ = cfg["databases"]
            _ = cfg["core"]
        except KeyError as e:
            raise ValueError(f"Error in config: Key {e} is missing.")
        return self


@dataclass
class DbConnectionParam:
    conn_str: str
    db: Optional[str] = field(default=None)
    username: Optional[str] = field(default=None)
    password: Optional[str] = field(default=None)
    host: Optional[str] = field(default=None)
    port: Optional[int] = field(default=None)

    def __post_init__(self):
        if self.conn_str:
            if not self.username:
                raise ValueError("Username is missing in the connection details.")

    @classmethod
    def from_uri(cls, uri: str) -> Self:
        if not uri:
            raise ValueError("Invalid URI: URI cannot be empty.")

        parsed = urlparse(uri)
        database_name = parsed.path.lstrip("/")

        # urlparse leaves percent-encoding in password and username. Safely unquote them.
        password = unquote(parsed.password) if parsed.password else None
        username = unquote(parsed.username) if parsed.username else None

        return cls(
            conn_str=uri,
            db=database_name if database_name else "postgres",
            username=username,
            password=password,
            host=parsed.hostname,
            port=parsed.port,
        )


class DbHelperTemplate(ABC):
    @abstractmethod
    def connect(self):
        raise NotImplementedError()

    def obscure_password(self, connection_str: str) -> str:
        # Simple obscuring for logging
        try:
            parsed = urlparse(connection_str)
            if parsed.password:
                # Replace the raw URL password substring
                return connection_str.replace(parsed.password, "***")
        except Exception:
            pass
        return connection_str


class PostgresDbHelper(DbHelperTemplate):
    def __init__(self, connection_str: str, docker_container: Optional[str] = None):
        self.params = DbConnectionParam.from_uri(connection_str)
        self.connection_str = connection_str
        self.docker_container = docker_container
        self.conn = None

    def connect(self) -> Self:
        lg.info(f"Connecting to PostgreSQL ({self.obscure_password(self.connection_str)})...")
        try:
            # autocommit=True is often needed for DDL (CREATE DATABASE etc)
            self.conn = psycopg.connect(self.connection_str, autocommit=True)
            lg.info("Connected to PostgreSQL.")
        except psycopg.Error as e:
            lg.exception("Failed to connect to PostgreSQL.")
            raise SystemExit(2) from e
        return self

    def _execute(self, query: str | sql.Composed, params: tuple = None, fetch: bool = False):
        try:
            with self.conn.cursor() as cur:
                cur.execute(query, params)
                if fetch:
                    return cur.fetchall()
        except psycopg.Error as e:
            lg.error(f"Query failed: {e}")
            raise

    def user_exists(self, username: str) -> bool:
        res = self._execute(
            "SELECT 1 FROM pg_roles WHERE rolname = %s", (username,), fetch=True
        )
        return bool(res)

    def create_user_if_not_exists(self, username: str, password: str, is_admin: bool = False):
        if self.user_exists(username):
            lg.info(f"User '{username}' already exists. Updating password...")
            self._execute(
                sql.SQL("ALTER USER {} WITH PASSWORD {}").format(
                    sql.Identifier(username), sql.Literal(password)
                )
            )
        else:
            lg.info(f"Creating user '{username}'...")
            stmt = sql.SQL("CREATE USER {} WITH PASSWORD {}").format(
                sql.Identifier(username), sql.Literal(password)
            )
            self._execute(stmt)

        if is_admin:
            lg.info(f"Granting CREATEDB to '{username}'...")
            self._execute(
                sql.SQL("ALTER USER {} CREATEDB").format(sql.Identifier(username))
            )

    def drop_user(self, username: str):
        if not self.user_exists(username):
            lg.warning(f"User '{username}' does not exist.")
            return

        lg.info(f"Dropping user '{username}'...")
        try:
            self._execute(
                sql.SQL("DROP USER {}").format(sql.Identifier(username))
            )
            lg.info(f"User '{username}' dropped successfully.")
        except psycopg.Error as e:
            lg.error(f"Failed to drop user '{username}': {e}")
            lg.warning("Note: Users cannot be dropped if they own database objects/privileges. You may need to REASSIGN OWNED or DROP OWNED first.")

    def database_exists(self, db_name: str) -> bool:
        res = self._execute(
            "SELECT 1 FROM pg_database WHERE datname = %s", (db_name,), fetch=True
        )
        return bool(res)

    def create_database(self, db_name: str, owner: Optional[str] = None):
        if self.database_exists(db_name):
            lg.info(f"Database '{db_name}' already exists.")
        else:
            lg.info(f"Creating database '{db_name}'...")
            self._execute(
                sql.SQL("CREATE DATABASE {}").format(sql.Identifier(db_name))
            )

        if owner:
            lg.info(f"Setting owner of '{db_name}' to '{owner}'...")
            self._execute(
                sql.SQL("ALTER DATABASE {} OWNER TO {}").format(
                    sql.Identifier(db_name), sql.Identifier(owner)
                )
            )

    def drop_database(self, db_name: str):
        if not self.database_exists(db_name):
            lg.warning(f"Database '{db_name}' does not exist.")
            return

        lg.info(f"Dropping database '{db_name}'...")
        try:
            # FORCE drop by terminating connections first (Postgres specific)
            self._execute(
                sql.SQL("""
                    SELECT pg_terminate_backend(pg_stat_activity.pid)
                    FROM pg_stat_activity
                    WHERE pg_stat_activity.datname = {}
                    AND pid <> pg_backend_pid();
                """).format(sql.Literal(db_name))
            )
            self._execute(
                sql.SQL("DROP DATABASE {}").format(sql.Identifier(db_name))
            )
            lg.info(f"Database '{db_name}' dropped successfully.")
        except psycopg.Error as e:
            lg.error(f"Failed to drop database '{db_name}': {e}")

    def setup_permissions_for_db(self, db_name: str, users: List[Dict[str, Any]], admin_user: Optional[str]):
        """
        Connects to the specific database and sets up permissions (Grants, Default Privileges).
        """
        # We need a new connection to the specific database to set local permissions
        db_conn_str = self.params.conn_str.rsplit("/", 1)[0] + f"/{db_name}"
        lg.info(f"Connecting to database '{db_name}' to apply permissions...")

        try:
            with psycopg.connect(db_conn_str, autocommit=True) as db_conn:
                with db_conn.cursor() as cur:
                    # 1. Revoke public access (good practice)
                    # cur.execute("REVOKE ALL ON SCHEMA public FROM PUBLIC")
                    # cur.execute("REVOKE ALL ON DATABASE {} FROM PUBLIC".format(db_name))
                    # Keeping it simple for now as per requirements, strictly following the roles requested.

                    # 2. Grant Admin Access if specified
                    if admin_user:
                        lg.info(f"Granting full admin access to '{admin_user}' on '{db_name}'...")
                        # Grant connect and create
                        cur.execute(
                            sql.SQL("GRANT ALL PRIVILEGES ON DATABASE {} TO {}").format(
                                sql.Identifier(db_name), sql.Identifier(admin_user)
                            )
                        )
                        # Grant schema usage/create
                        cur.execute(
                            sql.SQL("GRANT ALL PRIVILEGES ON SCHEMA public TO {}").format(
                                sql.Identifier(admin_user)
                            )
                        )
                        # Grant all on existing tables
                        cur.execute(
                            sql.SQL("GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO {}").format(
                                sql.Identifier(admin_user)
                            )
                        )
                        # Default privileges for future tables
                        cur.execute(
                            sql.SQL("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL PRIVILEGES ON TABLES TO {}").format(
                                sql.Identifier(admin_user)
                            )
                        )

                    # 3. Process each user based on their role
                    for user_cfg in users:
                        username = user_cfg["user"]
                        role = user_cfg.get("role", "read_only")

                        lg.info(f"Applying permissions for '{username}' as '{role}'...")

                        # Basic Connect
                        cur.execute(
                            sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
                                sql.Identifier(db_name), sql.Identifier(username)
                            )
                        )

                        if role == "owner":
                            # Owner is handled at DB creation level, but ensure they have usage
                            cur.execute(sql.SQL("GRANT ALL PRIVILEGES ON DATABASE {} TO {}").format(sql.Identifier(db_name), sql.Identifier(username)))
                            cur.execute(sql.SQL("GRANT ALL ON SCHEMA public TO {}").format(sql.Identifier(username)))
                            
                            # Grant all on existing objects
                            cur.execute(sql.SQL("GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO {}").format(sql.Identifier(username)))
                            cur.execute(sql.SQL("GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO {}").format(sql.Identifier(username)))
                            cur.execute(sql.SQL("GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO {}").format(sql.Identifier(username)))

                            # Default Privileges for future objects
                            cur.execute(sql.SQL("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL PRIVILEGES ON TABLES TO {}").format(sql.Identifier(username)))
                            cur.execute(sql.SQL("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL PRIVILEGES ON SEQUENCES TO {}").format(sql.Identifier(username)))
                            cur.execute(sql.SQL("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL PRIVILEGES ON FUNCTIONS TO {}").format(sql.Identifier(username)))

                        elif role == "read_write_create": # app_user1
                            # USAGE, CREATE on schema
                            cur.execute(sql.SQL("GRANT USAGE, CREATE ON SCHEMA public TO {}").format(sql.Identifier(username)))
                            
                            # RW on Tables/Sequences/Functions (Existing)
                            cur.execute(sql.SQL("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {}").format(sql.Identifier(username)))
                            cur.execute(sql.SQL("GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO {}").format(sql.Identifier(username)))
                            cur.execute(sql.SQL("GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO {}").format(sql.Identifier(username)))

                            # Default Privs (Future)
                            cur.execute(sql.SQL("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {}").format(sql.Identifier(username)))
                            cur.execute(sql.SQL("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO {}").format(sql.Identifier(username)))
                            cur.execute(sql.SQL("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO {}").format(sql.Identifier(username)))

                        elif role == "read_write": # app_user2
                            # USAGE on schema (No CREATE)
                            cur.execute(sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(sql.Identifier(username)))
                            
                            # RW on Tables/Sequences/Functions (Existing)
                            cur.execute(sql.SQL("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {}").format(sql.Identifier(username)))
                            cur.execute(sql.SQL("GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO {}").format(sql.Identifier(username)))
                            cur.execute(sql.SQL("GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO {}").format(sql.Identifier(username)))

                            # Default Privs (Future)
                            cur.execute(sql.SQL("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {}").format(sql.Identifier(username)))
                            cur.execute(sql.SQL("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO {}").format(sql.Identifier(username)))
                            cur.execute(sql.SQL("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO {}").format(sql.Identifier(username)))

                        elif role == "read_only": # read_user
                            # USAGE on schema
                            cur.execute(sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(sql.Identifier(username)))
                            # R on Tables
                            cur.execute(sql.SQL("GRANT SELECT ON ALL TABLES IN SCHEMA public TO {}").format(sql.Identifier(username)))
                            cur.execute(sql.SQL("GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO {}").format(sql.Identifier(username)))

                            # Default Privs
                            cur.execute(sql.SQL("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO {}").format(sql.Identifier(username)))
                            cur.execute(sql.SQL("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON SEQUENCES TO {}").format(sql.Identifier(username)))

                        else:
                            lg.warning(f"Unknown role '{role}' for user '{username}'. Skipping permissions.")

        except psycopg.Error as e:
            lg.error(f"Failed to apply permissions on database '{db_name}': {e}")
            raise

    def dump(self, db_name: str, output_path: Path) -> Path:
        """Dump an entire database to a file using pg_dump (custom format).

        Args:
            db_name:     Name of the database to back up.
            output_path: Destination file path. If a directory is given, a
                         timestamped filename is generated automatically.

        Returns:
            Path to the created dump file.
        """
        if output_path.is_dir():
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = output_path / f"{db_name}_{timestamp}.dump"

        output_path.parent.mkdir(parents=True, exist_ok=True)

        if not self.docker_container:
            raise ValueError("DOCKER_CONTAINER must be configured in 'core' section to use pg_dump via docker.")

        parsed = urlparse(self.params.conn_str)
        container_tmp_path = f"/tmp/{output_path.name}"

        lg.info(f"Dumping database '{db_name}' inside container '{self.docker_container}' → {output_path} ...")
        
        # 1. Run pg_dump inside the container
        cmd = [
            "docker", "exec",
            "-e", f"PGPASSWORD={parsed.password or ''}",
            self.docker_container,
            "pg_dump",
            "--format=custom",
            "--no-password",
            "--host=localhost",  # Run inside container, so host is localhost
            f"--port={parsed.port or 5432}",
            f"--username={parsed.username}",
            f"--file={container_tmp_path}",
            db_name,
        ]
        try:
            result = subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True,
            )
            if result.stderr:
                lg.debug(f"pg_dump stderr: {result.stderr.strip()}")
            
            # 2. Copy the file out of the container
            lg.info("Copying dump file from container to local path...")
            cp_cmd = ["docker", "cp", f"{self.docker_container}:{container_tmp_path}", str(output_path)]
            subprocess.run(cp_cmd, check=True, capture_output=True, text=True)
            
            # 3. Cleanup inside container
            rm_cmd = ["docker", "exec", self.docker_container, "rm", "-f", container_tmp_path]
            subprocess.run(rm_cmd, check=False, capture_output=True)

            lg.info(f"Dump completed successfully: {output_path}")
            return output_path
        except subprocess.CalledProcessError as e:
            lg.error(f"Command '{' '.join(e.cmd)}' failed (exit {e.returncode}): {e.stderr.strip()}")
            raise

    def restore(self, db_name: str, input_path: Path):
        """Restore an entire database from a pg_dump custom-format file.

        Args:
            db_name:    Target database name.
            input_path: Path to the .dump file produced by :meth:`dump`.
        """
        if not input_path.exists():
            raise FileNotFoundError(f"Dump file not found: {input_path}")

        if not self.docker_container:
            raise ValueError("DOCKER_CONTAINER must be configured in 'core' section to use pg_restore via docker.")

        parsed = urlparse(self.params.conn_str)
        container_tmp_path = f"/tmp/{input_path.name}"

        lg.info(f"Restoring '{db_name}' from {input_path} via container '{self.docker_container}' ...")
        
        try:
            # 1. Copy the dump file into the container
            lg.info("Copying dump file into the container...")
            cp_cmd = ["docker", "cp", str(input_path), f"{self.docker_container}:{container_tmp_path}"]
            subprocess.run(cp_cmd, check=True, capture_output=True, text=True)

            # 2. Run pg_restore inside the container
            cmd = [
                "docker", "exec",
                "-e", f"PGPASSWORD={parsed.password or ''}",
                self.docker_container,
                "pg_restore",
                "--no-password",
                "--exit-on-error",
                "-h", "localhost",
                "-p", str(parsed.port or 5432),
                "-U", parsed.username,
                "-d", db_name,
                container_tmp_path,
            ]
            
            result = subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True,
            )
            if result.stderr:
                lg.debug(f"pg_restore stderr: {result.stderr.strip()}")
            lg.info(f"Restore completed successfully for '{db_name}'.")

        except subprocess.CalledProcessError as e:
            lg.error(f"pg_restore failed (exit {e.returncode}).")
            if e.stderr:
                lg.error(f"Error details:\n{e.stderr.strip()}")
            raise
        finally:
            # 3. Cleanup inside container
            rm_cmd = ["docker", "exec", self.docker_container, "rm", "-f", container_tmp_path]
            subprocess.run(rm_cmd, check=False, capture_output=True)


def run_setup(args):
    """Execution logic for setting up databases and users"""
    helper = ConfigHelper(filepath=args.config)
    cfg = helper.validate_config().config

    CORE = cfg["core"]
    ADMIN = cfg.get("admin")
    DATABASES = cfg["databases"]

    # 1. Connect as Root to 'postgres' database
    db = PostgresDbHelper(
        connection_str=CORE["POSTGRES_URI"],
        docker_container=CORE.get("DOCKER_CONTAINER", "jfc_pgdb2")
    )
    db.connect()

    # 2. Setup Global Admin User
    admin_username = None
    if ADMIN:
        admin_username = ADMIN["user"]
        lg.info(f"Processing Admin User: {admin_username}")
        db.create_user_if_not_exists(
            username=admin_username,
            password=ADMIN["password"],
            is_admin=True
        )

    # 3. Process Databases and Users
    for db_cfg in DATABASES:
        db_name = db_cfg["db_name"]
        users = db_cfg.get("users", [])

        lg.info(f"--- Processing Database: {db_name} ---")

        # Create Users First (Global)
        owner_user = None
        for user in users:
            db.create_user_if_not_exists(user["user"], user["password"])
            if user.get("role") == "owner":
                owner_user = user["user"]

        # Create Database
        db.create_database(db_name, owner=owner_user)

        # Apply Permissions (requires connecting to the new DB)
        db.setup_permissions_for_db(db_name, users, admin_username)

        lg.info(f"--- Finished configuration for: {db_name} ---\n")

    lg.info("All database operations completed successfully.")


def run_init(args):
    """Initialize the configuration file via CLI command"""
    filepath = args.config
    if filepath.exists():
        lg.warning(f"Configuration file '{filepath}' already exists. Skipping initialization.")
        return

    lg.info(f"Initializing configuration file at '{filepath}'...")
    helper = ConfigHelper(filepath=filepath)
    # The __init__ of ConfigHelper already writes the default config if it doesn't exist.
    # So we just need to ensure the file was created.
    if filepath.exists():
        lg.info(f"Successfully created '{filepath}'.")
    else:
        # Fallback if ConfigHelper didn't write it (e.g. if logic changes)
        helper.write_config(DEFAULT_CONFIG)


def run_delete_user(args):
    """Logic to delete a specific user"""
    helper = ConfigHelper(filepath=args.config)
    cfg = helper.validate_config().config
    CORE = cfg["core"]

    db = PostgresDbHelper(
        connection_str=CORE["POSTGRES_URI"],
        docker_container=CORE.get("DOCKER_CONTAINER", "jfc_pgdb2")
    )
    db.connect()

    username = args.username
    lg.info(f"Are you sure you want to delete user '{username}'? This action cannot be undone.")
    choice = input("Type 'yes' to proceed: ")
    if choice.lower() != 'yes':
        lg.info("Operation cancelled.")
        return

    db.drop_user(username)


def run_delete_db(args):
    """Logic to delete a specific database"""
    helper = ConfigHelper(filepath=args.config)
    cfg = helper.validate_config().config
    CORE = cfg["core"]

    db = PostgresDbHelper(
        connection_str=CORE["POSTGRES_URI"],
        docker_container=CORE.get("DOCKER_CONTAINER", "jfc_pgdb2")
    )
    db.connect()

    db_name = args.db_name
    lg.warning(f"WARNING: This will PERMANENTLY DELETE database '{db_name}'.")
    lg.warning("All connections will be terminated.")
    choice = input("Type 'yes' to proceed: ")
    if choice.lower() != 'yes':
        lg.info("Operation cancelled.")
        return

    db.drop_database(db_name)


def run_dump(args):
    """Dump a database to a file using pg_dump via docker exec."""
    helper = ConfigHelper(filepath=args.config)
    cfg = helper.validate_config().config
    CORE = cfg["core"]

    db = PostgresDbHelper(
        connection_str=CORE["POSTGRES_URI"],
        docker_container=CORE.get("DOCKER_CONTAINER", "jfc_pgdb2")
    )
    # We do not strictly need psycopg to execute dump if it's all handled by pg_dump,
    # but connecting validates the python-side URL.
    db.connect()

    output_path = Path(args.output) if args.output else Path(".")
    db.dump(args.db_name, output_path)


def run_restore(args):
    """Restore a database from a pg_dump file via docker exec."""
    helper = ConfigHelper(filepath=args.config)
    cfg = helper.validate_config().config
    CORE = cfg["core"]
    DATABASES = cfg.get("databases", [])
    ADMIN = cfg.get("admin")

    db = PostgresDbHelper(
        connection_str=CORE["POSTGRES_URI"],
        docker_container=CORE.get("DOCKER_CONTAINER", "jfc_pgdb2")
    )
    db.connect()

    input_path = Path(args.input_file)
    db_name = args.db_name

    db_cfg = next((d for d in DATABASES if d["db_name"] == db_name), None)

    if args.create:
        lg.warning(f"--create flag set: database '{db_name}' will be dropped and recreated.")
        choice = input("Type 'yes' to proceed: ")
        if choice.lower() != 'yes':
            lg.info("Operation cancelled.")
            return
        if db.database_exists(db_name):
            db.drop_database(db_name)

    if not db.database_exists(db_name):
        if not db_cfg:
            lg.error(f"Database '{db_name}' not found in '{args.config}'. Please configure it or create the database and users first.")
            sys.exit(1)
        
        lg.info(f"Database '{db_name}' does not exist. Creating it using config parameters...")
        users = db_cfg.get("users", [])
        admin_username = ADMIN["user"] if ADMIN else None

        owner_user = None
        for user in users:
            db.create_user_if_not_exists(user["user"], user["password"])
            if user.get("role") == "owner":
                owner_user = user["user"]

        db.create_database(db_name, owner=owner_user)
        db.setup_permissions_for_db(db_name, users, admin_username)

    try:
        db.restore(db_name, input_path)
    except subprocess.CalledProcessError:
        lg.error(f"Failed to restore database '{db_name}'.")
        sys.exit(1)


def run_change_root_password(args):
    """Change the root user's password."""
    helper = ConfigHelper(filepath=args.config)
    cfg = helper.validate_config().config
    CORE = cfg["core"]

    db = PostgresDbHelper(
        connection_str=CORE["POSTGRES_URI"],
        docker_container=CORE.get("DOCKER_CONTAINER", "jfc_pgdb2")
    )
    db.connect()

    root_user = db.params.username
    if not root_user:
        lg.error("Could not determine root username from POSTGRES_URI.")
        sys.exit(1)

    lg.info(f"Updating password for root user '{root_user}'...")
    try:
        db._execute(
            sql.SQL("ALTER USER {} WITH PASSWORD {}").format(
                sql.Identifier(root_user), sql.Literal(args.new_password)
            )
        )
        lg.info(f"Successfully changed password for '{root_user}'.")
        lg.warning("IMPORTANT: Please update POSTGRES_URI in your config file to use the new password!")
    except psycopg.Error as e:
        lg.error(f"Failed to change password: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="PostgreSQL DB Helper")
    parser.add_argument(
        "-c", "--config", 
        type=Path, 
        default=CONFIG_FILE,
        help="Path to the secrets.postgres.toml configuration file."
    )

    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")

    # Command: init
    parser_init = subparsers.add_parser("init", help="Initialize the configuration file")
    parser_init.set_defaults(func=run_init)

    # Command: run (Default setup logic)
    parser_run = subparsers.add_parser("run", help="Run the database setup script (create DBs, users, roles)")
    parser_run.set_defaults(func=run_setup)

    # Command: delete-user
    parser_delete = subparsers.add_parser("delete-user", help="Delete a specific user/role")
    parser_delete.add_argument("username", type=str, help="Username to delete")
    parser_delete.set_defaults(func=run_delete_user)

    # Command: delete-db
    parser_delete_db = subparsers.add_parser("delete-db", help="Delete a specific database")
    parser_delete_db.add_argument("db_name", type=str, help="Database name to delete")
    parser_delete_db.set_defaults(func=run_delete_db)

    # Command: dump
    parser_dump = subparsers.add_parser("dump", help="Dump an entire database to a file (pg_dump custom format)")
    parser_dump.add_argument("db_name", type=str, help="Database name to dump")
    parser_dump.add_argument(
        "-o", "--output",
        type=str,
        default=None,
        help="Output file path or directory. Defaults to current directory with an auto-generated filename.",
    )
    parser_dump.set_defaults(func=run_dump)

    # Command: restore
    parser_restore = subparsers.add_parser("restore", help="Restore an entire database from a dump file (pg_restore)")
    parser_restore.add_argument("db_name", type=str, help="Target database name to restore into")
    parser_restore.add_argument("input_file", type=str, help="Path to the .dump file")
    parser_restore.add_argument(
        "--create",
        action="store_true",
        default=False,
        help="Drop and recreate the target database before restoring",
    )
    parser_restore.set_defaults(func=run_restore)

    # Command: change-root-password
    parser_change_root_password = subparsers.add_parser("change-root-password", help="Change the root user's password")
    parser_change_root_password.add_argument("new_password", type=str, help="The new password for the root user")
    parser_change_root_password.set_defaults(func=run_change_root_password)

    args = parser.parse_args()
    
    # Execute the selected function
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
