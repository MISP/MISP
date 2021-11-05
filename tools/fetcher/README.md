# MISP fetcher

Simple shell script to generate a zip file containing MISP with all submodules and composer libraries.

Simply run the script from its directory and use the zip's contents to update an airgapped MISP's codebase.

You will need to have composer installed and accessible

Assuming the standard MISP install path and www-data as your apache user, just run the following to update your MISP

```
unzip misp_flat.zip /var/www/MISP
chown -R www-data:www-data /var/www/MISP
```
