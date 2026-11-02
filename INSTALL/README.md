# INSTALL Documentation for the MISP Project.

To have a more web friendly view please visit the [mkdocs generated gh-pages site](https://misp.github.io/MISP/)

Currently the following install guides are being tested on a regular basis:
```
INSTALL.ubuntu2404.sh
```

The installers set up MISP 3.0 from the `3.0_wip` branch. They need MariaDB 10.11 or later (Ubuntu 24.04 ships it) and load `INSTALL/MARIADB.sql`; MySQL 8.4+ (`MYSQL.sql`) and PostgreSQL 16+ (`POSTGRESQL.sql`, see [CONFIG.postgresql.md](../docs/CONFIG.postgresql.md)) are supported by hand.

Files prefixed with 'CONFIG.' are CONFIGuration guides and not full blown INSTALL guides.

UPGRADE.ubuntu2404.sh upgrades an existing MISP 2.4 installation to 2.5. To go from 2.5 to 3.0, follow [UPGRADE.md](../docs/UPGRADE.md) instead. The script upgrades 2.4 to 2.5, provided you are on ubuntu 24.04 (if you are on an earlier distribution, make sure you run a distribution upgrade first).

**Something to keep in mind if you are updating from MISP 2.4 to 2.5, please make sure that you repopulate the new /var/www/MISP/app/Config/database.default.php rather than copying over your existing one from your old instance.**

UPDATE.md gives you a brief overview on how to update MISP to the latest version, as well as some other core dependencies that can be updated.

Install guides with the 'x' prefix, are marked as Experimental.
