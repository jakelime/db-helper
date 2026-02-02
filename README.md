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
