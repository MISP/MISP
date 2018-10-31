#### install etckeeper and sudo (optional)

```bash
su -
apt install -y etckeeper
apt install -y sudo
adduser misp sudo
```

##### add the misp user to staff and www-data (mandatory)
```bash
# Add the user to the staff group to be able to write to /usr/local/src
sudo adduser misp staff
sudo adduser misp www-data
logout
```
