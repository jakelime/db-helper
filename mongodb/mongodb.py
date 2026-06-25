# helpers/mongodb.py
# DB Helper updated on 28 Nov 2025
"""MongoDB helper script to interact with MongoDB databases.
- Creates database and collection if they do not exist.
- Provides function to create users with specific roles.
- Provides function to insert a document into a collection.
- Provides function to retrieve all documents from a collection.
"""

import argparse
import json
import logging
import sys
import tarfile
import io
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

try:
    from typing import Self
except ImportError:
    from typing_extensions import Self
from urllib.parse import urlparse

import pymongo as pymg
import tomlkit
from bson import json_util
from pymongo import errors as pymgErrors
from pymongo.write_concern import WriteConcern


# --- Basic Configuration Setup ---
def setup_basic_stream_logging():
    logging.basicConfig(
        # format="%(levelname)s:%(asctime)s:%(name)s: %(message)s",
        format="%(levelname)s:%(name)s: %(message)s",
        level=logging.INFO,
        # level=logging.DEBUG,
        stream=sys.stdout,
    )


setup_basic_stream_logging()
lg = logging.getLogger()
CONFIG_FILE = Path(__file__).parent / "secrets.mongodb.toml"
DEFAULT_CONFIG = {
    "core": {
        "MONGODB_URI": "mongodb://root:tzX4PtqOZSMsDDj3ikxU@localhost:27017/",
    },
    "databases": [
        {
            "db_name": "admin",
            "users": [
                {
                    "user": "dbadmin",
                    "password": "FuIquWNetLhqA9SFXqK",
                    "roles": [
                        "dbAdminAnyDatabase",
                        "userAdminAnyDatabase",
                        "readWriteAnyDatabase",
                    ],
                }
            ],
        },
        {
            "db_name": "db1",
            "users": [
                {
                    "user": "dbowner",
                    "password": "Or8RzpC0au5vfbZ94V47",
                    "roles": [
                        {"role": "dbOwner", "db": "db1"},
                    ],
                },
                {
                    "user": "appuser",
                    "password": "UkUIklEjPROEklUNhgWr",
                    "roles": [
                        {"role": "readWrite", "db": "db1"},
                    ],
                },
                {
                    "user": "reader",
                    "password": "CkJiz8ndjdFWKIjvaUd",
                    "roles": [
                        {"role": "read", "db": "db1"},
                    ],
                },
            ],
        },
        {
            "db_name": "db2",
            "users": [
                {
                    "user": "dbowner",
                    "password": "mpMiZBlnbweoyRWSHJQW",
                    "roles": [
                        {"role": "dbOwner", "db": "db2"},
                    ],
                },
                {
                    "user": "appuser",
                    "password": "uKP5sLvwNztGwLU4bli",
                    "roles": [
                        {"role": "readWrite", "db": "db2"},
                    ],
                },
                {
                    "user": "reader",
                    "password": "gOtLXkaZfo116ChJ9x9X",
                    "roles": [
                        {"role": "read", "db": "db2"},
                    ],
                },
            ],
        },
    ],
}


def chunked(
    iterable: List[Dict[str, Any]], size: int
) -> Iterable[List[Dict[str, Any]]]:
    """Yield successive chunks of given size from a list."""
    for i in range(0, len(iterable), size):
        yield iterable[i : i + size]


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
        """
        Reads configuration using tomlkit.
        """
        try:
            with open(self.filepath, "r", encoding="utf-8") as f:
                # tomlkit.load returns a MutableMapping (dict-like) object
                config = tomlkit.load(f)
            lg.debug("Configuration loaded successfully.")
            return config
        except Exception as e:
            lg.error(f"File read error in {self.filepath}: {e}")
            lg.warning("Using default configuration...")
            return None

    def write_config(self, config: dict) -> None:
        """
        Writes configuration using tomlkit.dump().
        This handles all nested lists, types, and escaping automatically.
        """
        try:
            with open(self.filepath, "w", encoding="utf-8") as f:
                tomlkit.dump(config, f)
            lg.info("Configuration written successfully.")
        except Exception as e:
            lg.error(f"Error writing configuration file: {e}")
            raise e

    def validate_config(self) -> Self:
        # For now, this does nothing
        pass


@dataclass
class DbConnectionParam:
    """
    A dataclass for holding database connection parameters,
    with validation and a factory method for MongoDB URIs.
    """

    conn_str: str
    db: Optional[str] = field(default=None)
    username: Optional[str] = field(default=None)
    password: Optional[str] = field(default=None)
    host: Optional[str] = field(default=None)
    port: Optional[int] = field(default=None)

    def __post_init__(self):
        """
        Validation method called after __init__.
        """
        # Ensure that if a conn_str is provided, authentication details are present.
        if self.conn_str:
            if not self.username:
                # Use a specific message to indicate the missing field
                raise ValueError("Username is missing in the connection details.")
            if not self.password:
                raise ValueError("Password is missing in the connection details.")

    @classmethod
    def from_mongo_uri(cls, uri: str) -> Self:
        """
        A factory method to create a DbConnectionParam instance by
        parsing a MongoDB connection URI.
        """
        if not uri:
            raise ValueError("Invalid Mongo URI for parsing: URI cannot be empty.")

        parsed = urlparse(uri)
        database_name = parsed.path.lstrip("/")

        return cls(
            conn_str=uri,
            db=database_name if database_name else None,
            username=parsed.username,
            password=parsed.password,
            host=parsed.hostname,
            port=parsed.port,
        )


class DbHelperTemplate(ABC):
    """Use this constructor to create
    database helpers for databases"""

    @abstractmethod
    def connect(self):
        raise NotImplementedError()

    def obscure_password(
        self, connection_str: str, mask: str = "***", partial: bool = False
    ) -> str:
        """
        Return a copy of the connection str URI with the password obscured.

        Examples
        --------
        >>> obscure_mongodb_password("mongodb://pproot:sFdDNzT5fyFPDaHSjEsS8x@localhost:27008/")
        'mongodb://pproot:***@localhost:27008/'

        >>> obscure_mongodb_password("mongodb+srv://user:Top$ecret@cluster0.example.net/db?retryWrites=true")
        'mongodb+srv://user:***@cluster0.example.net/db?retryWrites=true'

        >>> obscure_mongodb_password("mongodb://pproot@s1.example.net,s2.example.net/db")
        'mongodb://pproot@s1.example.net,s2.example.net/db'   # no password present -> unchanged

        Parameters
        ----------
        uri : str
            The MongoDB connection string.
        mask : str
            The replacement text for the password. Use only URL-safe characters if you
            care about strict RFC compliance; letters/numbers are safe. Default "REDACTED".
        partial : bool
            If True, only partially mask (keep first and last character when available).

        Notes
        -----
        * We rely on the fact that MongoDB credentials appear as:
            scheme://<username>:<password>@<hosts>[/...]
        We only modify the substring before the first '@' within the authority section.
        * If no password (no ':' in userinfo), the URI is returned unchanged.
        """
        uri = connection_str
        if not uri:
            raise KeyError("mongo_uri is not definted in the MongoLader")
        scheme_sep = "://"
        scheme_idx = uri.find(scheme_sep)
        if scheme_idx == -1:
            return uri  # Not a URI we recognize; leave unchanged.

        auth_start = scheme_idx + len(scheme_sep)

        # Determine where the authority (userinfo + hosts) segment ends
        # (first of '/', '?', or '#' after the scheme).
        end_authority = len(uri)
        for sep in ("/", "?", "#"):
            pos = uri.find(sep, auth_start)
            if pos != -1:
                end_authority = min(end_authority, pos)

        at_idx = uri.find("@", auth_start, end_authority)
        if at_idx == -1:
            return uri  # No userinfo -> nothing to mask.

        userinfo = uri[auth_start:at_idx]
        colon_idx = userinfo.find(":")
        if colon_idx == -1:
            return uri  # Username only -> nothing to mask.

        username = userinfo[:colon_idx]
        password = userinfo[colon_idx + 1 :]

        if partial and password:
            if len(password) == 1:
                masked = "*"
            elif len(password) == 2:
                masked = password[0] + "*"
            else:
                masked = password[0] + ("*" * (len(password) - 2)) + password[-1]
        else:
            masked = mask

        masked_userinfo = f"{username}:{masked}"
        return uri[:auth_start] + masked_userinfo + uri[at_idx:]


class DbHelper(DbHelperTemplate):
    """Placeholder for SQL Databases"""

    pass


class MongoDbHelperTemplate(DbHelperTemplate):
    params: DbConnectionParam
    client: Optional[pymg.MongoClient] = None
    db: Optional[pymg.database.Database] = None
    collection: Optional[pymg.collection.Collection] = None

    @abstractmethod
    def use_db(self):
        raise NotImplementedError()

    @abstractmethod
    def use_collection(self):
        raise NotImplementedError()

    def insert_one(
        self, record: Dict[str, Any], ordered: bool = True
    ) -> Optional[pymg.results.InsertOneResult]:
        """
        Insert a single document into the collection.
        Returns the result of the insert operation.
        """
        try:
            result = self.collection.insert_one(record)
            lg.debug(f"Inserted one document: {result.inserted_id}")
            return result
        except pymgErrors.PyMongoError as e:
            lg.error(f"Insert one failed: {e=}")
            return None

    def report_insert_error_details(self, e: pymgErrors.BulkWriteError) -> None:
        lg.warning("Bulk write error, some docs may have failed.")
        lg.warning(f"Error code: {e.code}:")
        for k, v in e.details.items():
            text = str(v)
            if len(text) > 50:
                text = text[:50] + "..."
            lg.warning(f"  {k}: {text}")

    def insert_data_chunked(self, data: list[Dict], debug_mode: bool = False) -> int:
        """
        Insert data using a pd.DataFrame or a list[Dict]
        Returns number of documents inserted.
        """
        total = 0
        lg.info(
            f"Inserting {len(data)} documents into '{self.collection.database.name}.{self.collection.name}' in batches of {self.batch_size}..."
        )
        for batch in chunked(data, self.batch_size):
            try:
                result = self.collection.insert_many(batch, ordered=False)
                total += len(result.inserted_ids)
            except pymgErrors.BulkWriteError as e:
                if debug_mode:
                    self.report_insert_error_details(e)
                if e.details:
                    total += e.details.get("nInserted", 0)
            except pymgErrors.PyMongoError as e:
                lg.exception(f"An error occurred during batch insert: {e}")
                break
        lg.info(f"  Done -> total documents inserted: {total}")
        return total

    def query_data(
        self, query: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Read documents from the collection based on a query.

        Parameters
        ----------
        query : Dict[str, Any], optional
            A dictionary specifying the selection criteria. If None, all documents
            in the collection will be returned. The default is None.  1

        Returns
        -------
        List[Dict[str, Any]]
            A list of documents matching the query.
        """
        if self.db is None or self.collection is None:
            raise RuntimeError("Database or collection not initialized.")
        if query is None:
            query = {}
        lg.info(
            f"Reading data from '{self.collection.database.name}.{self.collection.name}' with query: {query}"
        )
        try:
            cursor = self.collection.find(query)
            data = list(cursor)
            lg.info(f"fetched {len(data)} documents from {self.collection.name}")
            return data
        except pymgErrors.PyMongoError as e:
            lg.error(f"Failed to read data: {e}")
            return []

    def check_read_write_access(self) -> None:
        """
        Read: list DBs or collections.
        Write: insert + delete in a temporary collection.
        """
        lg.info("Verifying read/write access...")
        try:
            # Read check
            _ = self.client.list_database_names()
            _ = self.db.list_collection_names()

            # Write check using a temp collection
            temp_coll_name = "__dbsd_rw_check__"
            temp_coll = self.db.get_collection(
                temp_coll_name, write_concern=WriteConcern(w=1)
            )
            res = temp_coll.insert_one(
                {"_ts": datetime.now(timezone.utc), "_type": "rw_check"}
            )
            _ = temp_coll.delete_one({"_id": res.inserted_id})
            # Clean up: drop temp collection (best effort)
            try:
                self.db.drop_collection(temp_coll_name)
            except pymgErrors.PyMongoError:
                pass

            lg.info("Read/Write access: OK")
        except pymgErrors.PyMongoError as e:
            raise Exception("Read/Write access check failed.") from e


class MongoDbHelper(MongoDbHelperTemplate):
    def __init__(
        self,
        connection_str: str,
        db_name: Optional[str] = None,
        collection_name: str = "default_collection",
        batch_size: int = 1000,
        connect_timeout_ms: int = 20000,
        server_selection_timeout_ms: int = 30000,
        tz_aware: bool = True,
    ):
        self.params = DbConnectionParam.from_mongo_uri(connection_str)
        self.client = pymg.MongoClient(self.params.conn_str)
        self.db_name = db_name or self.params.db
        self.collection_name = collection_name
        self.batch_size = batch_size
        self._client_kwargs = {
            "connectTimeoutMS": connect_timeout_ms,
            "serverSelectionTimeoutMS": server_selection_timeout_ms,
            "tz_aware": tz_aware,
            "w": "majority",  # Ensure writes are acknowledged by the majority of nodes
        }

    def connect(self) -> Self:
        lg.info(
            f"Connecting to MongoDB({self.obscure_password(self.params.conn_str)})..."
        )
        try:
            self.client = pymg.MongoClient(self.params.conn_str, **self._client_kwargs)
            # Quick connectivity check
            self.client.admin.command("ping")
            lg.info("Connected to MongoDB.")
        except pymgErrors.PyMongoError as e:
            lg.exception("Failed to connect to MongoDB.")
            raise SystemExit(2) from e
        return self

    def use_db(self, db_name: Optional[str] = None) -> Self:
        if db_name:
            self.db = self.client[db_name]
        elif self.params.db:
            self.db = self.client[self.params.db]
        else:
            raise RuntimeError("Database name must be specified.")
        return self

    def use_collection(
        self, db_name: Optional[str] = None, collection_name: Optional[str] = None
    ) -> Self:
        db_name = db_name or self.db_name or self.params.db
        if not db_name:
            raise RuntimeError("Database name must be specified.")
        if self.db is None:
            self.use_db(db_name)
        collection_name = collection_name or self.collection_name
        if not collection_name:
            raise RuntimeError("Collection name must be specified.")
        self.collection = self.db.get_collection(collection_name)
        return self

    def init_collection(
        self,
        collection_name: Optional[str] = None,
        index_names: Optional[list[str]] = ["data_hash"],
    ) -> None:
        self.use_collection(collection_name=collection_name)
        if index_names:
            for id_name in index_names:
                self.collection.create_index(
                    [(id_name, pymg.ASCENDING)],
                    unique=True,
                    name=f"idx_unique_{id_name}",
                )
                lg.info(f"Index created successfully on '{id_name}'.")

    def insert_one(self, document: Dict[str, Any]) -> pymg.results.InsertOneResult:
        """Insert a document into the specified collection."""
        if self.collection is None:
            raise RuntimeError("Collection not selected. Use use_collection() first.")
        result = self.collection.insert_one(document)
        lg.debug(f"Document inserted with ID: {result.inserted_id}")
        return result

    def get_all_documents(self):
        """Retrieve all documents from the current collection."""
        return list(self.collection.find())

    def create_admin_user(self, username, password, roles) -> Dict[str, Any]:
        """Create a user in the admin database with specific roles."""
        current_db = self.db
        self.use_db("admin")
        try:
            result = self.get_or_create_user(username, password, roles)
            return result
        except pymgErrors.PyMongoError as e:
            lg.error(f"Failed to create user in admin database: {e}")
            raise
        finally:
            self.db = current_db  # Restore the original database context

    def create_user(
        self, username: str, password: str, roles: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Create a user with specific roles."""
        if self.db is None:
            raise RuntimeError("Database not selected. Use use_db() first.")
        try:
            result = self.db.command("createUser", username, pwd=password, roles=roles)
            lg.info(f"{username=} created with {roles=}; {result=}")
            return result
        except pymgErrors.OperationFailure as e:
            if e.code == 51003:  # User already exists
                lg.info(f"User {username} already exists in {self.db.name}")
                return {"ok": 1, "msg": "User already exists"}
            raise e

    def get_or_create_user(
        self, username: str, password: str, roles: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Get or create a user with specific roles.
        If the user already exists, it will return the user details.
        If not, it will create the user and return the details.
        """
        # Attempt to create first, if it fails because it exists, check info.
        # But actually create_user handles the already exists now if we modify it,
        # or we check first.

        # Original implementation checked first.
        try:
            # usersInfo requires rights.
            user_info = self.db.command("usersInfo", username)
            if user_info.get("users"):
                lg.info(f"{username=} already exists in db={self.db.name}")
                # Ideally we should update the user if needed, but for now just return
                return user_info["users"][0]
        except pymgErrors.PyMongoError:
            pass  # Try creating if we can't read info or it doesn't exist

        return self.create_user(username, password, roles)

    def drop_user(self, username: str, db_name: Optional[str] = None):
        """Drop a user from the database."""
        if db_name:
            self.use_db(db_name)
        elif self.db is None:
            raise RuntimeError("Database not selected.")

        try:
            self.db.command("dropUser", username)
            lg.info(f"User '{username}' dropped from '{self.db.name}'")
        except pymgErrors.OperationFailure as e:
            lg.error(f"Failed to drop user '{username}' from '{self.db.name}': {e}")

    def drop_database(self, db_name: str):
        """Drop a database."""
        try:
            self.client.drop_database(db_name)
            lg.info(f"Database '{db_name}' dropped.")
        except pymgErrors.PyMongoError as e:
            lg.error(f"Failed to drop database '{db_name}': {e}")

    def get_orphaned_users(self) -> List[Dict[str, str]]:
        """Identify orphaned users (users tagged to non-existent databases)."""
        active_dbs = set(self.client.list_database_names())
        lg.info(f"Active databases: {active_dbs}")

        # Access admin database to see system users
        admin_db = self.client["admin"]
        # system.users collection contains all users
        try:
            # We might need high privileges for this
            all_users = list(admin_db["system.users"].find())
        except pymgErrors.PyMongoError:
            # Try command alternative if direct collection access fails (e.g. strict mongo)
            # But 'usersInfo' {user:1, db:1} generally checks one db.
            # Listing all users usually requires querying system.users or command usersInfo on admin with checking all dbs?
            # Actually 'usersInfo': 1 on admin db returns users on admin db.
            # To list all users on all DBs, usually one queries the system.users collection in admin.
            lg.warning(
                "Could not access admin.system.users directly. Attempting to match against known users config might be better, but assuming admin access."
            )
            return []

        orphaned = []
        for user_doc in all_users:
            user_name = user_doc.get("user")
            auth_db = user_doc.get("db")

            if auth_db not in active_dbs and auth_db not in [
                "admin",
                "local",
                "config",
            ]:
                orphaned.append({"user": user_name, "db": auth_db})

        return orphaned

    def clean_orphaned_users(self):
        """Removes orphaned users."""
        orphaned = self.get_orphaned_users()
        if not orphaned:
            lg.info("No orphaned users found.")
            return

        lg.info(f"Found {len(orphaned)} orphaned users.")
        for target in orphaned:
            lg.info(
                f"Orphaned: User '{target['user']}' linked to missing DB '{target['db']}'"
            )

        # In a script we might ask for confirmation, here we assume if called it is desired or handled by caller
        # But let's add a force or confirm mechanism in CLI.
        # For now, just execute as per request 'clean-users' implies action.

        for target in orphaned:
            try:
                # To delete a user, we must run command on the auth db (even if it doesn't exist as a filled db, the context matters)
                # Wait, if the DB doesn't exist, we can still select it contextually in client to run dropUser?
                # Yes, in MongoDB 'use db' is virtual until data is written, but commands can be run contextually.
                target_db = self.client[target["db"]]
                target_db.command("dropUser", target["user"])
                lg.info(
                    f"Dropped orphaned user '{target['user']}' from '{target['db']}'"
                )
            except pymgErrors.PyMongoError as e:
                lg.error(f"Failed to drop orphaned user '{target['user']}': {e}")

    # --- Dump / Restore ---

    SYSTEM_DBS = {"admin", "local", "config"}

    def dump_databases(
        self,
        out_dir: Path,
        db_names: Optional[List[str]] = None,
        compress: bool = False,
    ) -> None:
        """
        Dump one or more databases to JSON files or a compressed tar.gz.

        If compress=False:
            Each collection is saved as:
                <out_dir>/<db_name>/<collection_name>.json
        If compress=True:
            Each database is saved as:
                <out_dir>/<db_name>.tar.gz

        Parameters
        ----------
        out_dir : Path
            Root output directory. Created if it does not exist.
        db_names : list[str] | None
            Databases to dump. If None, all non-system databases are dumped.
        compress : bool
            If True, compress each database into a tar.gz file.
        """
        out_dir.mkdir(parents=True, exist_ok=True)

        if db_names is None:
            all_dbs = self.client.list_database_names()
            db_names = [d for d in all_dbs if d not in self.SYSTEM_DBS]

        lg.info(f"Dumping {len(db_names)} database(s) to '{out_dir}' ...")
        for db_name in db_names:
            db_obj = self.client[db_name]

            try:
                collections = db_obj.list_collection_names(
                    filter={"type": "collection"}
                )
            except pymgErrors.OperationFailure as e:
                lg.warning(
                    f"  [{db_name}] Cannot list collections (permission denied): {e.details.get('errmsg', e)}. Skipping."
                )
                continue

            lg.info(f"  [{db_name}] {len(collections)} collection(s)")

            if compress:
                tar_path = out_dir / f"{db_name}.tar.gz"
                try:
                    with tarfile.open(tar_path, "w:gz") as tar:
                        for coll_name in collections:
                            try:
                                docs = list(db_obj[coll_name].find())
                            except pymgErrors.OperationFailure as e:
                                lg.warning(
                                    f"    -> {coll_name}: skipped (permission denied): {e.details.get('errmsg', e)}"
                                )
                                continue
                            json_data = json.dumps(
                                docs, default=json_util.default, indent=2
                            ).encode("utf-8")
                            info = tarfile.TarInfo(name=f"{db_name}/{coll_name}.json")
                            info.size = len(json_data)
                            tar.addfile(tarinfo=info, fileobj=io.BytesIO(json_data))
                            lg.info(
                                f"    -> {coll_name}: {len(docs)} document(s) -> {db_name}.tar.gz"
                            )
                except Exception as e:
                    lg.error(f"  [{db_name}] Error creating archive: {e}")
            else:
                db_out = out_dir / db_name
                db_out.mkdir(parents=True, exist_ok=True)
                for coll_name in collections:
                    try:
                        docs = list(db_obj[coll_name].find())
                    except pymgErrors.OperationFailure as e:
                        lg.warning(
                            f"    -> {coll_name}: skipped (permission denied): {e.details.get('errmsg', e)}"
                        )
                        continue
                    out_file = db_out / f"{coll_name}.json"
                    with open(out_file, "w", encoding="utf-8") as f:
                        json.dump(docs, f, default=json_util.default, indent=2)
                    lg.info(
                        f"    -> {coll_name}: {len(docs)} document(s) -> {out_file}"
                    )

        lg.info("Dump complete.")

    def restore_from_dir(self, db_src: Path, target_db, drop_before_restore: bool):
        json_files = list(db_src.glob("*.json"))
        lg.info(
            f"  [{target_db.name}] {len(json_files)} collection file(s) (uncompressed)"
        )

        for json_file in json_files:
            coll_name = json_file.stem
            with open(json_file, "r", encoding="utf-8") as f:
                docs = json.load(f, object_hook=json_util.object_hook)
            self.restore_docs(target_db, coll_name, docs, drop_before_restore)

    def restore_from_tar(self, tar_src: Path, target_db, drop_before_restore: bool):
        lg.info(f"  [{target_db.name}] Reading from archive {tar_src.name}")
        try:
            with tarfile.open(tar_src, "r:gz") as tar:
                members = [m for m in tar.getmembers() if m.name.endswith(".json")]
                lg.info(
                    f"  [{target_db.name}] {len(members)} collection file(s) in archive"
                )

                for member in members:
                    # m.name is typically "<db_name>/<coll_name>.json"
                    coll_name = Path(member.name).stem
                    f = tar.extractfile(member)
                    if f is None:
                        continue
                    content = f.read().decode("utf-8")
                    docs = json.loads(content, object_hook=json_util.object_hook)
                    self.restore_docs(target_db, coll_name, docs, drop_before_restore)
        except Exception as e:
            lg.error(f"  [{target_db.name}] Failed to restore from {tar_src.name}: {e}")

    def restore_docs(
        self, target_db, coll_name: str, docs: list, drop_before_restore: bool
    ):
        if not docs:
            lg.info(f"    -> {coll_name}: 0 documents, skipping.")
            return

        coll = target_db[coll_name]
        if drop_before_restore:
            coll.drop()
            lg.info(f"    -> {coll_name}: dropped (clean restore).")

        result = coll.insert_many(docs, ordered=False)
        lg.info(
            f"    -> {coll_name}: inserted {len(result.inserted_ids)}/{len(docs)} document(s)."
        )

    def restore_databases(
        self,
        src_dir: Path,
        target_uri: str,
        db_names: Optional[List[str]] = None,
        drop_before_restore: bool = False,
    ) -> None:
        """
        Restore dumped JSON files into a target MongoDB instance.
        Supports both directories of JSON files and .tar.gz archives.

        Parameters
        ----------
        src_dir : Path
            Root directory produced by dump_databases(), or a specific .tar.gz file.
        target_uri : str
            Connection string for the destination MongoDB server.
        db_names : list[str] | None
            Sub-directories (databases) to restore. If None, all found in src_dir.
        drop_before_restore : bool
            If True, drop each collection before inserting. Useful for a clean restore.
        """
        target_client = pymg.MongoClient(target_uri)
        try:
            target_client.admin.command("ping")
            lg.info(f"Connected to target: {self.obscure_password(target_uri)}")
        except pymgErrors.PyMongoError as e:
            lg.error(f"Failed to connect to target MongoDB: {e}")
            raise

        if not src_dir.exists():
            lg.error(f"Source path {src_dir} does not exist.")
            target_client.close()
            return

        # Handle case where user provided a single .tar.gz file
        if src_dir.is_file() and src_dir.name.endswith(".tar.gz"):
            db_name_from_file = src_dir.name[:-7]
            if db_names is None or db_name_from_file in db_names:
                self.restore_from_tar(
                    src_dir, target_client[db_name_from_file], drop_before_restore
                )
            lg.info("Restore complete.")
            target_client.close()
            return

        if db_names is None:
            subdirs = [p.name for p in src_dir.iterdir() if p.is_dir()]
            tarfiles = [p.name[:-7] for p in src_dir.glob("*.tar.gz")]
            db_names = list(set(subdirs + tarfiles))

        lg.info(f"Restoring {len(db_names)} database(s) from '{src_dir}' ...")
        for db_name in db_names:
            tar_src = src_dir / f"{db_name}.tar.gz"
            dir_src = src_dir / db_name
            target_db = target_client[db_name]

            if tar_src.exists():
                self.restore_from_tar(tar_src, target_db, drop_before_restore)
            elif dir_src.exists():
                self.restore_from_dir(dir_src, target_db, drop_before_restore)
            else:
                lg.warning(
                    f"  [{db_name}] Source directory or tarball not found, skipping."
                )

        lg.info("Restore complete.")
        target_client.close()


def run_init(cfg, db: MongoDbHelper):
    DATABASES = cfg.get("databases", [])
    for cfgdb in DATABASES:
        db_name = cfgdb.get("db_name")
        if not db_name:
            continue
        try:
            db.use_db(db_name)
            users = cfgdb.get("users", [])

            if users:
                lg.info(f"Processing {db_name=}, {len(users)=} users defined...")
                for user in users:
                    username = user["user"]
                    password = user["password"]
                    roles = user["roles"]
                    try:
                        db.get_or_create_user(
                            username=username, password=password, roles=roles
                        )
                    except Exception as e:
                        lg.error(f"Failed to create user {username} in {db_name}: {e}")
            else:
                lg.info(
                    f"No users defined for {db_name}. Accessing DB to ensure connection."
                )
        except Exception as e:
            lg.error(f"Error processing database {db_name}: {e}")


def run_clean_users(db: MongoDbHelper):
    db.clean_orphaned_users()


def run_delete_user(db: MongoDbHelper, user: str, target_db: str):
    try:
        db.drop_user(user, target_db)
    except Exception as e:
        lg.error(f"Error deleting user: {e}")


def run_delete_db(db: MongoDbHelper, target_db: str):
    # Safety check
    if target_db in ["admin", "local", "config"]:
        lg.error(f"Cannot delete system database '{target_db}'")
        return
    db.drop_database(target_db)


def run_dump(
    db: MongoDbHelper, out_dir: Path, db_names: Optional[List[str]], compress: bool
):
    """Dump one or all databases to JSON files."""
    db.dump_databases(
        out_dir=out_dir, db_names=db_names if db_names else None, compress=compress
    )


def run_restore(
    db: MongoDbHelper,
    cfg: dict,
    src_dir: Path,
    target_uri: Optional[str],
    db_names: Optional[List[str]],
    drop: bool,
):
    """Restore JSON dump files into a target MongoDB instance."""
    uri = target_uri or cfg.get("core", {}).get("MONGODB_URI", "")
    db.restore_databases(
        src_dir=src_dir,
        target_uri=uri,
        db_names=db_names if db_names else None,
        drop_before_restore=drop,
    )


def main():
    parser = argparse.ArgumentParser(description="MongoDB Helper Script")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Command: init
    subparsers.add_parser("init", help="Generate secrets.mongodb.toml only")

    # Command: run
    subparsers.add_parser(
        "run", help="Initialize users and databases from secrets.toml"
    )

    # Command: clean-users
    subparsers.add_parser("clean-users", help="Clean up orphaned user accounts")

    # Command: delete-user
    parser_del_user = subparsers.add_parser(
        "delete-user", help="Delete a specific user"
    )
    parser_del_user.add_argument("--user", required=True, help="Username to delete")
    parser_del_user.add_argument(
        "--db", required=True, help="Database the user belongs to"
    )

    # Command: delete-db
    parser_del_db = subparsers.add_parser(
        "delete-db", help="Delete a specific database"
    )
    parser_del_db.add_argument("--db", required=True, help="Database name to delete")

    # Command: dump
    parser_dump = subparsers.add_parser(
        "dump",
        help="Dump one or all databases to JSON files (for migration)",
    )
    parser_dump.add_argument(
        "--db",
        dest="db_names",
        nargs="+",
        metavar="DB",
        default=None,
        help="Database(s) to dump. If omitted, all non-system databases are dumped.",
    )
    parser_dump.add_argument(
        "--out",
        type=Path,
        default=None,
        metavar="DIR",
        help="Output directory (default: ./dump_<timestamp>)",
    )
    parser_dump.add_argument(
        "--compress",
        action="store_true",
        help="If set, compress the output to a tar.gz file for each database",
    )

    # Command: restore
    parser_restore = subparsers.add_parser(
        "restore",
        help="Restore a dump directory into a target MongoDB instance",
    )
    parser_restore.add_argument(
        "--src",
        type=Path,
        required=True,
        metavar="DIR",
        help="Source dump directory (produced by the 'dump' command)",
    )
    parser_restore.add_argument(
        "--target-uri",
        default=None,
        metavar="URI",
        help="Target MongoDB connection URI. Defaults to the URI in secrets.mongodb.toml.",
    )
    parser_restore.add_argument(
        "--db",
        dest="db_names",
        nargs="+",
        metavar="DB",
        default=None,
        help="Database(s) to restore. If omitted, all databases in --src are restored.",
    )
    parser_restore.add_argument(
        "--drop",
        action="store_true",
        default=False,
        help="Drop each collection before inserting (clean restore).",
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    if args.command == "init":
        # Just generates the configuration file if it doesn't exist
        if CONFIG_FILE.exists():
            example_file = CONFIG_FILE.with_name("secrets.mongodb.example.toml")
            if not example_file.exists():
                _ = ConfigHelper(filepath=example_file)
                lg.info(
                    f"'{CONFIG_FILE.name}' already exists. Generated '{example_file.name}' instead."
                )
            else:
                lg.info(
                    f"'{CONFIG_FILE.name}' and '{example_file.name}' already exist."
                )
        else:
            _ = ConfigHelper()
        return

    # For other commands, load config
    helper = ConfigHelper()
    try:
        helper.validate_config()
        cfg = helper.config
    except Exception as e:
        lg.error(f"Config validation failed: {e}")
        sys.exit(1)

    # Establish DB Connection for subsequent commands
    core_cfg = cfg.get("core", {})
    mongo_uri = core_cfg.get("MONGODB_URI")
    if not mongo_uri:
        lg.error("MONGODB_URI not found in the configuration.")
        sys.exit(1)

    db = MongoDbHelper(connection_str=mongo_uri, connect_timeout_ms=5000)
    db.connect()

    if args.command == "run":
        run_init(cfg, db)
    elif args.command == "clean-users":
        run_clean_users(db)
    elif args.command == "delete-user":
        run_delete_user(db, args.user, args.db)
    elif args.command == "delete-db":
        run_delete_db(db, args.db)
    elif args.command == "dump":
        out = args.out or Path(f"./mgdbdump_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        run_dump(db, out_dir=out, db_names=args.db_names, compress=args.compress)
    elif args.command == "restore":
        run_restore(
            db=db,
            cfg=cfg,
            src_dir=args.src,
            target_uri=args.target_uri,
            db_names=args.db_names,
            drop=args.drop,
        )


if __name__ == "__main__":
    main()
