# Cerebrate Migrations using Phinx

## For users

### Updating

- Use the build in migration tool of Cerebrate via the UI / API
- Alternatively, run `/var/www/cerebrate/bin/cake Migration migrate` to execute the updates.

## For developers

- Run `vendor/bin/phinx create MyNewMigration`
- This will create a new migration called YYYYMMDDHHMMSS_my_new_migration.php where you need to populate the change() function
