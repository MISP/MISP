# SMIME patch

## Create SMIME directory
```bash
mkdir /var/www/MISP/.smime
```
## Copy your public x509 certificate (for signing) in PEM format
```bash
cp email@address.com.pem /var/www/MISP/.smime/email@address.com.pem
```
## Copy your private key for signing email
```bash
cp email@address.com.key /var/www/MISP/.smime/email@address.com.key
```
### Set permissions
```bash
chown www-data:www-data /var/www/MISP/.smime
chmod 500 /var/www/MISP/.smime
chmod 440 /var/www/MISP/.smime/*
```

## Export the public certificate (for Encipherment) to the webroot
```bash
cp public_certificate.pem /var/www/MISP/app/webroot/public_certificate.pem
```
Due to this action, the MISP users will be able to download your public certificate (for Encipherment) by clicking on the footer

### Set permissions
```bash
chown www-data:www-data /var/www/MISP/app/webroot/public_certificate.pem
chmod 440 /var/www/MISP/app/webroot/public_certificate.pem
```
## Configure the section "SMIME" in the server settings (Administration -> Server settings -> Encryption tab)

# S/MIME self-signed key creation with OpenSSL

## CA key creation

`openssl req -nodes -new -x509 -days 3650 -newkey rsa:4096 -keyout ca.key -out ca.crt -extensions v3_ca -subj "/CN=MISP-CA"`

## MISP instance key + CSR request

`openssl req -nodes -new -newkey rsa:4096 -keyout info@mymisp.key -out info\@mymisp.csr`

## Sign S/MIME key

`openssl x509 -req -days 3650 -in info\@mymisp.csr -CA ca.crt -CAkey ca.key -set_serial 1 -out info\@mymisp.crt -addtrust emailProtection -addreject clientAuth -addreject serverAuth -trustout -extensions smime`

## Convert CRT file to PEM format

`openssl x509 -in info\@mymisp.crt -out info\@mymisp.pem -outform PEM`
