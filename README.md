# Database Helper

Helps to manage databases instances by creating
database and db_user accounts.

## MongoDB

### Quickstart for mongo

1. `cd mongodb`
1. `uv run python mongodb.py --help`
1. `uv run python mongodb.py init` to generate configuration file `secrets.mongodb.toml`.
1. Edit `secrets.mongodb.toml` accordingly:

   1. Make sure that `MONGODB_URI='mongodb://root:tzX4PtqOZSMsDDj3ikxU@localhost:27017'` is correct.
   1. You can create any number of databases, using TOML section formatting.
   1. Within the databases, you can create any number of users.

1. If you have specified new databases and users to be created, trigger by running `uv run python mongodb.py run`

### `clean-users` — Remove orphaned users

Finds and drops users whose authentication database no longer exists.

```bash
uv run python mongodb.py clean-users
```

### `delete-user` — Delete a specific user

```bash
uv run python mongodb.py delete-user --user <username> --db <database>
```

### `delete-db` — Delete a specific database

```bash
uv run python mongodb.py delete-db --db <database>
```

### `dump` — Export data for migration

Dumps one or all non-system databases to JSON files. Each collection is saved as
`<out_dir>/<db_name>/<collection_name>.json`. Uses `bson.json_util` to correctly
handle MongoDB-specific types (`ObjectId`, `datetime`, etc.).

```bash
# Dump all databases (auto-names output dir with timestamp)
uv run python mongodb.py dump

# Dump specific databases into a named output directory
uv run python mongodb.py dump --db myapp_db another_db --out ./uat-dump

# Compress each database's dump into a tar.gz archive
uv run python mongodb.py dump --compress
```

### `restore` — Import a dump into another MongoDB instance

Reads JSON files produced by `dump` and inserts them into a target MongoDB server.
Useful for migrating data from UAT → DEV (or any environment-to-environment transfer).

```bash
# Restore all databases from a dump directory into a different server
uv run python mongodb.py restore --src ./uat-dump --target-uri "mongodb://root:pass@dev-host:27017/"

# Restore specific databases only
uv run python mongodb.py restore --src ./uat-dump --db myapp_db --target-uri "mongodb://..."

# Clean restore: drop each collection before inserting
uv run python mongodb.py restore --src ./uat-dump --target-uri "mongodb://..." --drop
```

> **Tip — UAT → DEV migration workflow:**
>
> 1. On UAT server: `uv run python mongodb.py dump --out ./uat-dump`
> 2. Copy `./uat-dump/` to DEV server (e.g. via `scp` or shared volume).
> 3. On DEV server: `uv run python mongodb.py restore --src ./uat-dump --target-uri "mongodb://root:pass@dev-host:27017/" --drop`

---

## PostgreSQL

### Quickstart for postgres

1. `cd postgres`
1. `uv run python postgres.py --help`
1. `uv run python postgres.py init` to generate configuration file `secrets.postgres.toml`.
1. Edit `secrets.postgres.toml` accordingly:

   1. Make sure that `POSTGRES_URI` is correct.
   1. You can create any number of databases, using TOML section formatting.
   1. Within the databases, each user is assigned a `role`: `owner`, `read_write_create`, `read_write`, or `read_only`.

1. If you have specified new databases and users to be created, trigger by running `uv run python postgres.py run`

### `delete-user` — Delete a specific user/role

```bash
uv run python postgres.py delete-user <username>
```

### `delete-db` — Delete a specific database

```bash
uv run python postgres.py delete-db <db_name>
```

### `dump` / `restore` — Export/import a database (pg_dump custom format)

```bash
uv run python postgres.py dump <db_name> --output ./backup.dump
uv run python postgres.py restore <db_name> ./backup.dump --create
```

### `change-root-password` — Rotate the root user's password

```bash
uv run python postgres.py change-root-password <new_password>
```

---

## Helper functions

### Zip

```bash
python -c "import shutil; shutil.make_archive('dump_20260507_144952', 'zip', '.', 'dump_20260507_144952')"

python -c "import zipfile; zipfile.ZipFile('dump_20260507_144952.zip').extractall('.')"
python -c "import zipfile; zipfile.ZipFile('dump_20260507_144952.zip').extractall('./restored')"

# List contents without extracting:
python -c "import zipfile; [print(f) for f in zipfile.ZipFile('dump_20260507_144952.zip').namelist()]"
```

### Secrets

```bash
python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"

# Generates a secured secret key for use as password of 1+21 char in length
# The first char is always a letter, no dash and underscore for easy copypaste and url-safe.
## 22 chars password
python -c "import secrets, string; alph = string.ascii_letters + string.digits; print(secrets.choice(string.ascii_letters) + ''.join(secrets.choice(alph) for _ in range(21)))"
## 32 chars password
python -c "import secrets, string; alph = string.ascii_letters + string.digits; print(secrets.choice(string.ascii_letters) + ''.join(secrets.choice(alph) for _ in range(31)))"

# Generates a secret key
## 32 chars
python -c "import secrets; print(secrets.token_urlsafe(32)[:32])"
```
