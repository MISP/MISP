#### install etckeeper and sudo (optional)


```bash
# <snippet-begin 0_sudoKeeper.sh>
# check if sudo is installed
checkSudoKeeper () {
  echo "Checking for sudo and installing etckeeper"
  if [[ ! -f $(which sudo) ]]; then
    echo "Please enter your root password below to install etckeeper"
    su -c "apt install etckeeper -y"
    echo "Please enter your root password below to install sudo"
    su -c "apt install sudo -y"
    echo "Please enter your root password below to add $MISP_USER to sudo group"
    su -c "adduser $MISP_USER sudo"
    echo "We added $MISP_USER to group sudo and now we need to log out and in again."
    exit
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
