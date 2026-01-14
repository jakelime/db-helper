from pymongo import MongoClient

# 1. Connect to MongoDB (ensure your user has admin privileges)
client = MongoClient("mongodb://adminUser:password@localhost:27017/?authSource=admin")


def cleanup_orphaned_users():
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
    cleanup_orphaned_users()
