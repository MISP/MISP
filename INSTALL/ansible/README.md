MISP - Ansible installation script
----------------------------------------

- V0.1
  * Nginx support only
  * Backup script provided

Instructions
----------------------------------------
- From the ansible repository, run the following command:

```bash
ansible-playbook -i <host>, misp.yml -K -u <user>
```

- Update the self-signed certificate in /etc/nginx/ssl
- Create and export your GPG key:

```bash
sudo -u www-data gpg --homedir /opt/misp-server/misp/.gnupg --gen-key
sudo -u www-data gpg --homedir /opt/misp-server/misp/.gnupg --export --armor YOUR-EMAIL > /opt/misp-server/misp/app/webroot/gpg.asc
```

- Login with:
  * user: admin@admin.test
  * password: admin
and update the admin password

- Configure MISP in administration panel, server settings

Notes
----------------------------------------
- the user must have admin rights
- a self-signed certificate is generated to allow you to test the installation
- installation directory is: /opt/misp-server/misp
- backup directory is: /opt/misp-server/backup

Backup script
----------------------------------------
If enabled, a backup script create each day a new archive with a MySQL misp database dump and misp files to allow easy restore.
- these archives are created in: /opt/misp-server/backup
- a script to easy restore MISP from an archive is provided in the same directory
- to use the restore script, login as misp user and run the following command:

```bash
./misp_restore <archive_timestamp>.tar.gz
```

