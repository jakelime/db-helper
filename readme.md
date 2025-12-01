# Database Helper

Helps to manage databases instances by creating
database and db_user accounts.

## Quickstart for MongoDB

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
