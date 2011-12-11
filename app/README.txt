
TODOs
-----
Contact reporter
- allow custom message

Signature
- add "no-ids-signature" option

Auth
- Use captcha authenticaiton
- cleanup ACL and do it using the CakePHP concept

implement auditing/logging system
- add / edit events and signatures
- failed / success logins (with source IP, headers,...)

Security
- apply CSRF checks by enabling security modules and rewriting some parts
- force cookie reset after login


INSTALLATION INSTRUCTIONS
-------------------------
Download CakePHP 1.3 and copy the app to the app directory.

First you need to edit the files in the /app/config directory.
# (or copy your local config settings including the salts and passwords)
# cp app/config/* /Users/chri/tmp/sshfs/sig/app/config/

Then set the permissions correctly using the following commands as root:
chown -R chri:www-data sig
chmod -R 750 sig
chmod -R g+s sig
cd sig/app/
chmod -R g+w tmp
 




Recommended patches
-------------------
By default CakePHP exposes his name and version in email headers. Apply a patch to remove this behavior.

