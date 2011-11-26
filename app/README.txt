
TODOs
-----
Contact reporter
- allow custom message

Signature
- add "no-ids-signature" option

implement auditing/logging system
- add / edit events and signatures
- failed / success logins (with source IP, headers,...)



INSTALLATION INSTRUCTIONS
-------------------------
First you need to edit the files in the /app/config directory.
# (or copy your local config settings including the salts and passwords)
# cp app/config/* /Users/chri/tmp/sshfs/sig/app/config/

Then set the permissions correctly using the following commands as root:
chown -R chri:www-data sig
chmod -R 750 sig
chmod -R g+s sig
cd sig/app/
chmod -R g+w tmp
 

