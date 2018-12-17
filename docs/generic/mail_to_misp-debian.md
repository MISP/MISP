#### Install mail to misp
--------------------

!!! warning
    mail_to_misp has **lief** as a dependency, lief only has an .egg for Python3.6 NOT Python3.7<br />
    If you have python3.7 installed make sure **virtualenv** uses **python3.6**<br />
    ```bash
    virtualenv -p python3.6 venv
    ```

```bash
cd /usr/local/src/
sudo apt-get install -y cmake
git clone https://github.com/MISP/mail_to_misp.git
git clone https://github.com/stricaud/faup.git
cd faup
sudo mkdir -p build
cd build
cmake .. && make
sudo make install
sudo ldconfig
cd ../../mail_to_misp
virtualenv -p python3.6 venv
./venv/bin/pip install -r requirements.txt
cp mail_to_misp_config.py-example mail_to_misp_config.py

sed -i "s/^misp_url\ =\ 'YOUR_MISP_URL'/misp_url\ =\ 'http:\/\/localhost'/g" /usr/local/src/mail_to_misp/mail_to_misp_config.py
sed -i "s/^misp_key\ =\ 'YOUR_KEY_HERE'/misp_key\ =\ '${AUTH_KEY}'/g" /usr/local/src/mail_to_misp/mail_to_misp_config.py
```
