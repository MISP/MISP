MISP-BACKUP
-----------

shell script for making a MISP backup

Installation
============

Modify config file:
````
cp misp-backup.conf.sample misp-backup.conf
#adjust values
vi misp-backup.conf
````

Running
=======

run the script:
````
sh misp-backup.sh
````

Open
====

````
    sample files
    server certificates for sync connections
    organisation logos (though this isn't as important, but it's still annoying to lose them)

````


Licence
=======

See LICENSE
initial idea based daverstephens on https://github.com/daverstephens/The-SOC-Shop


MISP-RESTORE
------------

This script aims at restoring a backup made with `misp-backup.sh` script found in this folder.

Pre-requisites
==============
- Apache, MISP and mariaDB/MySQL should be installed before running this script.
- The versions of MISP software backed up and restored should be the same.  (e.g. restore fiels database of a MISP v2.4.86 on a server with the same version of MISP)
- This script only restores the data on a database installed on localhost.

Description
===========
 This script restores following file/DB from an archive created with `misp-backup.sh`:
 - app/Config PHP files
 - app/webroot/img orgs and custom files
 - app/webroot/files 
 - GnuPG files
 - MYSQL User used in archive or its password if exists
 - MISP database
 


Run the script
==============

```
run ./misp-restore.sh  PATH_TO_ARCHIVE.tar.gz
```
