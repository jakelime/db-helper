# Database Helper

Helps to manage databases instances by creating
database and db_user accounts.

## Quickstart for MongoDB

1. `pip install -r requirements.txt -i https://artifact.stengglink.com/repository/pypi-proxy/simple`

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
python -c "import secrets, base64; print(base64.urlsafe_b64encode(secrets.token_bytes(15)).decode('utf-8').replace('-', '').replace('_', '').strip('=')[:20])"
python -c "import secrets, base64; print(base64.urlsafe_b64encode(secrets.token_bytes(15)).decode('utf-8').replace('-', '').replace('_', '').strip('=')[:20].lower())"
```

## Docker utilities

```bash
docker run -it --rm -v datashare_media:/datashare_media -v ${MOUNTED_DATA_DISK}/jetforge/www/:/datashare_mounted busybox
```
