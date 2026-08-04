```bash
# <snippet-begin 2_gnupg.sh>
# Generate GnuPG key
setupGnuPG () {
  if [ ! -d $PATH_TO_MISP/.gnupg ]; then
    # The email address should match the one set in the config.php
    # set in the configuration menu in the administration menu configuration file
    echo "%echo Generating a default key
      Key-Type: default
      Key-Length: $GPG_KEY_LENGTH
      Subkey-Type: default
      Name-Real: $GPG_REAL_NAME
      Name-Comment: $GPG_COMMENT
      Name-Email: $GPG_EMAIL_ADDRESS
      Expire-Date: 0
      Passphrase: $GPG_PASSPHRASE
      # Do a commit here, so that we can later print "done"
      %commit
    %echo done" > /tmp/gen-key-script

    $SUDO_WWW gpg --homedir $PATH_TO_MISP/.gnupg --batch --gen-key /tmp/gen-key-script

    # Export the public key to the webroot
    $SUDO_WWW sh -c "gpg --homedir $PATH_TO_MISP/.gnupg --export --armor $GPG_EMAIL_ADDRESS" | $SUDO_WWW tee $PATH_TO_MISP/app/webroot/gpg.asc
  fi
}
# <snippet-end 2_gnupg.sh>
```
