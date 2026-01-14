# helpers/mongodb.py
# DB Helper updated on 28 Nov 2025
"""MongoDB helper script to interact with MongoDB databases.
- Creates database and collection if they do not exist.
- Provides function to create users with specific roles.
- Provides function to insert a document into a collection.
- Provides function to retrieve all documents from a collection.
"""

import logging
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Self
from urllib.parse import urlparse

import pymongo as pymg
import tomlkit
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
CONFIG_FILE = Path(__file__).parent / "secrets.toml"
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
        cfg = self.config
        try:
            _ = cfg["databases"]
        except tomlkit.exceptions.NonExistentKey:
            raise ValueError("Error in config: 'databases' key is missing.")
        return self


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
        result = self.db.command("createUser", username, pwd=password, roles=roles)
        lg.info(f"{username=} created with {roles=}; {result=}")
        return result

    def get_or_create_user(
        self, username: str, password: str, roles: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Get or create a user with specific roles.
        If the user already exists, it will return the user details.
        If not, it will create the user and return the details.
        """
        try:
            user = self.db.command("usersInfo", username)
            if user["users"]:
                lg.info(f"{username=} already exists in db={self.db.name}")
                return user["users"][0]
        except pymgErrors.PyMongoError as e:
            lg.warning(f"Failed to retrieve user info: {e}")

        return self.create_user(username, password, roles)

    def run(self):
        if not self.params.db:
            self.create_user_in_admin_db(
                username="hello",
                password="world",
                roles=[{"role": "readWrite", "db": "test"}],
            )


def main():
    # 1. Initialize ConfigHelper and load configuration
    # ConfigHelper is used to load the configuration,
    # it will read from config.toml or create a default one if it doesn't exist.
    helper = ConfigHelper()
    cfg = helper.validate_config().config

    CORE = cfg["core"]
    DATABASES = cfg["databases"]

    db = MongoDbHelper(connection_str=CORE["MONGODB_URI"], connect_timeout_ms=2000)
    db.connect()
    for cfgdb in DATABASES:
        db_name = cfgdb["db_name"]
        db.use_db(db_name)
        users = cfgdb.get("users", [])
        if not users:
            continue  # Skip if no users defined for this db
        lg.info(f"processing {db_name=}, {len(users)=} users defined...")
        for user in users:
            username = user["user"]
            password = user["password"]
            roles = user["roles"]
            db.get_or_create_user(username=username, password=password, roles=roles)


if __name__ == "__main__":
    main()
