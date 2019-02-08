#### install etckeeper and sudo (optional)


```bash
# <snippet-begin 0_sudoKeeper.sh>
# check if sudo is installed
checkSudoKeeper () {
  if [ -ne $(which sudo) ]; then
    su -c "apt install -y etckeeper"
    su -c "apt install -y sudo"
    # TODO: Fix this, user misp might not exist
    su -c "adduser misp sudo"
  else
    sudo apt install etckeeper -y
  fi
}
# <snippet-end 0_sudoKeeper.sh>
```

##### add the misp user to staff and www-data (mandatory)
```bash
# <snippet-begin add-user.sh>
# Add the user to the staff group to be able to write to /usr/local/src
# TODO: Fix this, user misp might not exist
sudo adduser misp staff
sudo adduser misp www-data
# <snippet-end add-user.sh>
# Logout and back in to make the group changes take effect.
logout
```
