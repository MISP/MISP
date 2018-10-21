# 0. Upgrade procedure from v2.3 to v2.4
!!! notice
    It is assumed that the upgrade happens from an up-to-date 2.3 instance<br />
    It is a good idea to back up your MISP installation and data before upgrading to a new release.

# 1. git pull the latest version of MISP from  the [repo](https://github.com/MISP/MISP.git)
```
cd /var/www/MISP
git pull
git checkout tags/$(git describe --tags `git rev-list --tags --max-count=1`)
# if the last shortcut doesn't work, specify the latest version manually
# example: git checkout tags/v2.4.XY
# the message regarding a "detached HEAD state" is expected behaviour
# (you only have to create a new branch, if you want to change stuff and do a pull request for example)
```

# 2. Update CakePHP to the latest supported version
```
cd /var/www/MISP
rm -rf app/Lib/cakephp/
git submodule update --init --recursive
```

# 3. delete everything from MISP's cache directory to get rid of the cached models
```
find /var/www/MISP/app/tmp/cache/ -type f -not -name 'empty' -delete
```

# 4. clear the old submodule cached entry for CakeResque
```
cd /var/www/MISP
git rm --cached app/Plugin/CakeResque/
```

# 5. make sure that your database is backed up
```
mysqldump -u [misp_mysql_user] -p [misp_database] > /home/[my_user]/misp_db_pre_migration.sql
```

# 6. upgrade your database with the new tables / fields introduced in 2.4
```
cd /var/www/MISP/INSTALL
mysql -u [misp_mysql_user] -p [misp_database] < upgrade_2.4.sql
```

# 7. run the upgrade script from within the application
!!! notice
    simply navigate to Administration -> Administrative Tools -> "Upgrade to 2.4"<br />
    Once that has completed successfully run the 2.3->2.4 cleanup script<br />
    simply navigate to Administration -> Administrative Tools -> "2.3->2.4 cleanup script"

!!! notice
    If everything went fine, switch the system to live:<br />
    Administration -> Server Settings -> MISP Settings -> MISP.live -> True

!!! notice
    If nothing happens, please check the permissions of the config files in /var/www/MISP/app/Config/<br />
    and make sure the webserver has the write permissions on them:
    ```bash
    chown -R www-data:www-data /var/www/MISP/app/Config/
    ```

Let us know if you run into any issues during or after the upgrade
