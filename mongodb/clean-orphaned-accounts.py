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
from pymongo import MongoClient
from pymongo import errors as pymgErrors
from pymongo.write_concern import WriteConcern


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
        "MONGODB_URI": "mongodb://root:myNotVerySecretPassword@localhost:27017/",
    },
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
            _ = cfg["core"]
        except tomlkit.exceptions.NonExistentKey:
            raise ValueError("Error in config: 'core' key is missing.")
        return self


def main():
    helper = ConfigHelper()
    cfg = helper.validate_config().config
    CORE = cfg["core"]
    client = MongoClient(CORE["MONGODB_URI"])
    cleanup_orphaned_users(client)


def cleanup_orphaned_users(client):
    # 2. Get list of all current active databases
    active_dbs = set(client.list_database_names())
    print(f"Active databases: {active_dbs}")

    # 3. Get all users globally by querying the admin database
    # Users are stored in admin.system.users
    admin_db = client.admin
    all_users = list(admin_db.system.users.find())

    orphaned_users = []

    print("\nChecking for orphaned users...")
    for user_doc in all_users:
        user_name = user_doc["user"]
        auth_db = user_doc["db"]

        # A user is orphaned if their 'home' (auth) database is not in active_dbs
        # Exception: system databases like 'admin', 'local', 'config'
        if auth_db not in active_dbs and auth_db not in ["admin", "local", "config"]:
            orphaned_users.append({"user": user_name, "db": auth_db})
            print(
                f"Found orphaned user: '{user_name}' linked to deleted DB: '{auth_db}'"
            )

    # 4. Delete the orphaned users
    if not orphaned_users:
        print("No orphaned users found.")
        return

    confirm = input(
        f"\nFound {len(orphaned_users)} orphaned users. Delete them? (y/n): "
    )
    if confirm.lower() == "y":
        for target in orphaned_users:
            try:
                # To delete a user, you must run the command against their auth database
                target_db = client[target["db"]]
                target_db.command("dropUser", target["user"])
                print(f"Successfully deleted {target['user']} from {target['db']}")
            except Exception as e:
                print(f"Failed to delete {target['user']}: {e}")
    else:
        print("Cleanup cancelled.")


if __name__ == "__main__":
    main()
