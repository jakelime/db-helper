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
