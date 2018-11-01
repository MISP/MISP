#### Install viper framework (with a virtualenv)
-----------------------

!!! warning
    Viper has **lief** as a dependency, lief only has an .egg for Python3.6 NOT Python3.7<br />
    If you have python3.7 installed make sure **virtualenv** uses **python3.6**<br />
    ```bash
    virtualenv -p python3.6 venv
    ```

```bash
cd /usr/local/src/
sudo apt-get install -y libssl-dev swig python3-ssdeep p7zip-full unrar-free sqlite python3-pyclamd exiftool radare2 python3-magic python3-sqlalchemy python3-prettytable
git clone https://github.com/viper-framework/viper.git
cd viper
virtualenv -p python3 venv
git submodule update --init --recursive
./venv/bin/pip install scrapy
./venv/bin/pip install -r requirements.txt
sed -i '1 s/^.*$/\#!\/usr\/local\/src\/viper\/venv\/bin\/python/' viper-cli
sed -i '1 s/^.*$/\#!\/usr\/local\/src\/viper\/venv\/bin\/python/' viper-web
## /!\ Check wtf is going on with yara.
###sudo pip3 uninstall yara -y
###./venv/bin/pip uninstall yara -y
/usr/local/src/viper/viper-cli -h
/usr/local/src/viper/viper-web -p 8888 -H 0.0.0.0 &
echo 'PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/usr/local/src/viper"' |sudo tee /etc/environment
sed -i "s/^misp_url\ =/misp_url\ =\ http:\/\/localhost/g" ~/.viper/viper.conf
sed -i "s/^misp_key\ =/misp_key\ =\ ${AUTH_KEY}/g" ~/.viper/viper.conf
# Reset admin password to: admin/Password1234
sqlite3 ~/.viper/admin.db 'UPDATE auth_user SET password="pbkdf2_sha256$100000$iXgEJh8hz7Cf$vfdDAwLX8tko1t0M1TLTtGlxERkNnltUnMhbv56wK/U="'
# Add viper-web to rc.local to be started on boot
sudo sed -i -e '$i \sudo -u misp /usr/local/src/viper/viper-web -p 8888 -H 0.0.0.0 > /tmp/viper-web_rc.local.log &\n' /etc/rc.local
```
