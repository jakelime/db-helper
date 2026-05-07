# Database Helper

Helps to manage databases instances by creating
database and db_user accounts.

## Quickstart for MongoDB

1. `pip install -r requirements.txt -i https://artifact.privaterepo.com/repository/pypi-proxy/simple`

1. [For the first time] Run the script. `python mongodb.py`.

   - This will generate the `secrets.toml` file.
   - This run will fail due to incorrect default root creds.
   - `CTRL-C` to end script.

1. Go to `secrets.toml`. Now, make sure that
   `MONGODB_URI='mongodb://root:tzX4PtqOZSMsDDj3ikxU@localhost:27017'` is correct.

1. Edit your configuration accordingly

   - You can create any number of databases.
   - You can create any number of users, users are subset of the databases to be
     created in the database itself.

## MongoDB CLI Commands

All commands are run from the `mongodb/` directory:

```bash
cd db-helper/mongodb/
```

### `run` — Initialize databases and users

Creates databases and users defined in `secrets.mongodb.toml`.

```bash
python mongodb.py run
```

### `clean-users` — Remove orphaned users

Finds and drops users whose authentication database no longer exists.

```bash
python mongodb.py clean-users
```

### `delete-user` — Delete a specific user

```bash
python mongodb.py delete-user --user <username> --db <database>
```

### `delete-db` — Delete a specific database

```bash
python mongodb.py delete-db --db <database>
```

### `dump` — Export data for migration

Dumps one or all non-system databases to JSON files. Each collection is saved as
`<out_dir>/<db_name>/<collection_name>.json`. Uses `bson.json_util` to correctly
handle MongoDB-specific types (`ObjectId`, `datetime`, etc.).

```bash
# Dump all databases (auto-names output dir with timestamp)
python mongodb.py dump

# Dump specific databases into a named output directory
python mongodb.py dump --db myapp_db another_db --out ./uat-dump
```

### `restore` — Import a dump into another MongoDB instance

Reads JSON files produced by `dump` and inserts them into a target MongoDB server.
Useful for migrating data from UAT → DEV (or any environment-to-environment transfer).

```bash
# Restore all databases from a dump directory into a different server
python mongodb.py restore --src ./uat-dump --target-uri "mongodb://root:pass@dev-host:27017/"

# Restore specific databases only
python mongodb.py restore --src ./uat-dump --db myapp_db --target-uri "mongodb://..."

# Clean restore: drop each collection before inserting
python mongodb.py restore --src ./uat-dump --target-uri "mongodb://..." --drop
```

> **Tip — UAT → DEV migration workflow:**
>
> 1. On UAT server: `python mongodb.py dump --out ./uat-dump`
> 2. Copy `./uat-dump/` to DEV server (e.g. via `scp` or shared volume).
> 3. On DEV server: `python mongodb.py restore --src ./uat-dump --target-uri "mongodb://root:pass@dev-host:27017/" --drop`

---

## Known Issues

Postgres helper is alot more complex than this simple implementation.

1. Postgres users are not created and stored in the same database.
1. Postgres user permissions can be tuned to table levels. For example;
   if you created tables `[Table0, Table1, Table2]` when the
   user is first created, then create `Table3`. The user will not by
   default be granted permissions to `Table4`.
1. A more straightforward approach would be simply using `dbOwner`
   role to the application account. However, this would not satisfy
   the Principle of Least Privilege in cybersecurity.
1. There are various workarounds, such as initializing the app using
   `dbOwner`, then downgrade the connection string to `read, write` only.

   [**TODO**] OR, workout exactly all the SQL commands required to satisfy complexities
   from Postgres.

   - Grant RW permissions and all future permissions to all tables
   - Grant CREATE table permissions
   - Grant user access to the database only
   - Take care not to allow table name modifications,
     and/or delete operations.

## Helper functions

```bash


python -c "import shutil; shutil.make_archive('dump_20260507_144952', 'zip', '.', 'dump_20260507_144952')"

python -c "import zipfile; zipfile.ZipFile('dump_20260507_144952.zip').extractall('.')"
python -c "import zipfile; zipfile.ZipFile('dump_20260507_144952.zip').extractall('./restored')"

# List contents without extracting:
python -c "import zipfile; [print(f) for f in zipfile.ZipFile('dump_20260507_144952.zip').namelist()]"


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
