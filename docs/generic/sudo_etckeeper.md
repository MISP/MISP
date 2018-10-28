#### install etckeeper and sudo (optional)
```bash
su -
apt install -y etckeeper
apt install -y sudo
adduser misp sudo
# Add the user to the staff group to be able to write to /usr/local/src
adduser misp staff
```
