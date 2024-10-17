**Important Note**

It is **very strongly recommended** to upgrade MISP via the web interface. This documentation may not always be up-to-date and will require you to fix permissions if you want to use the web interface to run the updates in the future.


# Point release updates
!!! notice
    In general, updating MISP between point releases (for example 2.4.50 -> 2.4.53) happens with one of the following two options (both are to be executed as root).

## Option 1

To update to the latest commit from the 2.4 branch simply pull the latest commit
```bash
cd /var/www/MISP
# Replace www-data with whoever is your webserver user (apache/httpd)
sudo -u www-data git pull origin 2.4
sudo -u www-data git submodule update --init --recursive
```

## Option 2

If you want to stick to a point release instead of pulling the latest commit directly
```bash
cd /var/www/MISP
git fetch
git checkout tags/$(git describe --tags `git rev-list --tags --max-count=1`)
git submodule update --init --recursive
```

# Upgrades from minor version to another
!!! notice
    If you would like to upgrade from a minor version to another, look at the Upgrade MISP guides instead (such as [2.3.xyz -> 2.4.xyz](archive/old-2_3to2_4-UPGRADE.md))

!!! warning
    If for any reason something goes wrong with the above instructions, walk through the following manual upgrade

# 1. Update the MISP code to the latest hotfix.
As user root, do the following:

```bash
cd /var/www/MISP
git fetch
git checkout tags/$(git describe --tags `git rev-list --tags --max-count=1`)
# if the last shortcut doesn't work, specify the latest version manually
# example: git checkout tags/v2.4.XY
# the message regarding a "detached HEAD state" is expected behaviour
# (you only have to create a new branch, if you want to change stuff and do a pull request for example)
```

# 2. Update CakePHP to the latest supported version (if for some reason it doesn't get updated automatically with git submodule)
```bash
cd /var/www/MISP
git submodule update --init --recursive
```

# 3. Update Mitre's STIX and its dependencies
```bash
cd /var/www/MISP/app/files/scripts/
rm -rf python-cybox
rm -rf python-stix
sudo -u www-data git clone https://github.com/CybOXProject/python-cybox.git
sudo -u www-data git clone https://github.com/STIXProject/python-stix.git
cd /var/www/MISP/app/files/scripts/python-cybox 
python3 setup.py install 
cd /var/www/MISP/app/files/scripts/python-stix 
python3 setup.py install
```

# 4. Update mixbox to accommodate the new STIX dependencies:
```bash
cd /var/www/MISP/app/files/scripts/
rm -rf mixbox
sudo -u www-data git clone https://github.com/CybOXProject/mixbox.git
cd /var/www/MISP/app/files/scripts/mixbox
python3 setup.py install
```

# 5. install PyMISP
```bash
cd /var/www/MISP/PyMISP
python3 setup.py install
```

# 6. For RHEL: enable python3 for php-fpm
```bash
echo 'source scl_source enable rh-python36' >> /etc/opt/rh/rh-php71/sysconfig/php-fpm
sed -i.org -e 's/^;\(clear_env = no\)/\1/' /etc/opt/rh/rh-php71/php-fpm.d/www.conf
systemctl restart rh-php71-php-fpm.service
```

# 7. Update CakeResque and its dependencies
```bash
cd /var/www/MISP/app

# Edit composer.json so that cake-resque is allowed to be updated
# "kamisama/cake-resque": ">=4.1.2"

vim composer.json
php composer.phar self-update
# if behind a proxy use HTTP_PROXY="http://yourproxy:port" php composer.phar self-update
php composer.phar update


# To use the scheduler worker for scheduled tasks, do the following:
cp -fa /var/www/MISP/INSTALL/setup/config.php /var/www/MISP/app/Plugin/CakeResque/Config/config.php
```

# 8. Make sure all file permissions are set correctly
```bash
find /var/www/MISP -type d -exec chmod g=rx {} \;
chmod -R g+r,o= /var/www/MISP/
chown -R www-data:www-data /var/www/MISP/
```

# 9. Restart the CakeResque workers
```bash
su - www-data -s /bin/bash -c 'bash /var/www/MISP/app/Console/worker/start.sh'
```

!!! note
    You can also do this using the MISP application by navigating to the workers tab in the server settings and clicking on the "Restart all workers" button.

# 10. Add any new dependencies that might have been added since you've last updated (shown below)

# 11. Add requirements for the pubsub optional feature
```bash
pip install pyzmq
```
