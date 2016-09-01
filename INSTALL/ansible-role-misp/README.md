# Ansible Role: Malware Information Sharing Platform (MISP)

An Ansible Role that installs and configures MISP on Ubuntu trusty (14.04) and xenial (16.04).

## Requirements

Review and set Role default variables.

## Role Structure

    ```shell
    ansible-role-misp
    ├── defaults
    │   └── main.yml
    ├── handlers
    │   └── main.yml
    ├── README.md
    ├── tasks
    │   ├── apache.yml
    │   ├── cert.yml
    │   ├── deps.yml
    │   ├── gpg.yml
    │   ├── harden.yml
    │   ├── main.yml
    │   ├── misp.yml
    │   ├── modsec.yml
    │   ├── mysql.yml
    │   ├── perms.yml
    │   └── worker.yml
    ├── templates
    │   ├── bootstrap.php.j2
    │   ├── config.php.j2
    │   ├── core.php.j2
    │   ├── database.php.j2
    │   ├── gpgconf.j2
    │   └── misp-ssl.conf.j2
    └── vars
        └── main.yml
    ```

## Role Variables

Available variables are detailed below (see 'defaults/main.yml') and can be broken into the following categories:

MySQL:

    mysql_server: localhost
    mysql_db: misp_db_name
    mysql_user: misp_db_user
    mysql_pass: misp_db_pass
    mysql_root_user: root
    mysql_root_pass: ""

The database server, databse name, username, and password which will be used for the MISP setup. It is recommended to store passwords in Ansible's Vault.

SSL:

    ssl_cert_generate: true
    ssl_cert_path: /etc/apache2/ssl
    ssl_cert_owner: root
    ssl_cert_group: root
    ssl_cert_path_perms: 0700
    ssl_cert_files_perms: 0600
    ssl_cert_file: "{{ ssl_cert_path }}/misp.crt"
    ssl_key_file: "{{ ssl_cert_path }}/misp.key"
    ssl_cert_rsa_size: "4096"
    ssl_cert_validity: "365"
    ssl_cert_common_name: "Cert_CN"
    ssl_cert_organization: "Cert_ORG"
    ssl_cert_state: "State"
    ssl_cert_locality: "State"
    ssl_cert_country: "SC"
    ssl_cert_subject: "/C={{ ssl_cert_country }}/ST={{ ssl_cert_state }}/L={{ ssl_cert_locality }}/O={{ ssl_cert_organization }}/CN={{ ssl_cert_common_name }}"

A self-signed certificate will be generated as part of the Ansible Role. The above variables control the various aspects of the self-signed certificate generation such as certificate and key directories, ownership and permissions, and the certificate configurations.

Apache:

    apache_enable_mods:
      - rewrite
      - headers
      - ssl
      - security2

The Apache2 modules to be enabled including ModSecurity2 (see below ModSecurity2 variables).

    apache_disable_mods: []

The Apache2 modules that will be disabled once specified. If specific modules need to disabled, add them to this variable.

    apache_disable_sites:
      - 000-default
      - default-ssl

The Apache2 default sites to be disabled. This a step out of many to hardening Apache2 setup.

    apache_sites_available_path: /etc/apache2/sites-available
    apache_sites_enabled_path: /etc/apache2/sites-enabled
    apache_server_root: /etc/apache2
    apache_server_admin: admin@yourdomain.local
    apache_server_name: "{{ ansible_hostname }}"
    apache_document_root: /var/www/MISP/app/webroot
    apache_web_owner: www-data
    apache_web_group: www-data
    apache_ssl_port: 443
    apache_ssl_protocols: "all -SSLv2 -SSLv3"
    apache_ssl_ciphers: "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256"
    apache_ssl_ciper_order: "on"
    apache_ssl_compression: "off"
    apache_ssl_tickets: "off"
    apache_ssl_stapling_status: "on"
    apache_ssl_stapling_rtimeout: 5
    apache_ssl_stapling_rerrors: "off"
    apache_ssl_stapling_cache: "shmcb:/var/run/ocsp(128000)"
    apache_ssl_error_log: "/var/log/apache2/misp-ssl.local_error.log"
    apache_ssl_custom_log: "/var/log/apache2/misp-ssl.local_access.log combined"
    apache_ssl_conf_cmd: "Curves secp384r1"
    apache_hsts_max_age: 15768000
    apache_x_frame: DENY
    apache_x_content: nosniff
    apache_x_xss: "1; mode=block"

MISP Apache site is configured using a template (see 'templates/misp-ssl.conf.j2). Most of the variables above are used to fill in the Jinja2 template. The SSL configurations were adopted from the [Mozilla's Server Side TLS Guidelines](https://wiki.mozilla.org/Security/Server_Side_TLS). Other variables are used to keep Ansible tasks clean and highly configurable.

ModSecurity2:

    config_modsecurity: true

When true, the Ansible Role will configure ModSecurity2 in 'DetectionOnly' mode and the OWASP Core Rule Set (base and optional) from the [OWASP ModSecurity Core Rule Set (CRS) Official Repository](https://github.com/SpiderLabs/owasp-modsecurity-crs).

    modsec_dir: /etc/modsecurity
    modsec_owasp_dir: "{{ modsec_dir }}/owasp-crs"
    modsec_rule_engine: "DetectionOnly"
    modsec_req_body_limit: "33554432"
    modsec_req_body_inmem_limit: "33554432"

The Ansible Role will configure ModSecurity2 in 'DetectionOnly' mode and the OWASP Core Rule Set (base and optional).

PHP:

    php_disable_functions: "pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,exec,system,shell_exec,passthru,"

PHP functions to be disabled to limit attack surface.

    php5_ini: /etc/php5/apache2/php.ini
    php7_ini: /etc/php/7.0/apache2/php.ini
    php5_redis: /etc/php5/cli/conf.d/20-redis.ini
    php7_redis: /etc/php/7.0/cli/conf.d/20-redis.ini

PHP version-specfic configuration file paths.

Salt:

    enable_auto_salt: true

When true, the Ansible Role will take advantge of Ansible's Password Lookup module to automatically generate the 32 byte long string. The resulting 'salt' is then used as an Ansible fact to be inserted into the MISP config.php template (see 'tasks/misp.yml' and 'templates/config.php.j2).

    hardcoded_salt: ""

When 'enable_auto_salt' is set to false, the 32 byte long string must be generated/obtained somewhere else and hardcoded into the variable above. If 'enable_auto_salt' is true, then the variable does not need to be set.

MISP:

    misp_root_path: /var/www/MISP
    misp_worker_path: /var/www/MISP/app/Console/worker
    enable_misp_worker: true

MISP-specific variables including MISP installation directory, MISP worker path, and whether to start the MISP workers.

GPG:

    gpg_enc_key_dir: /var/www/MISP/.gnupg
    gpg_pub_key_dir: /var/www/MISP/app/webroot

GPG encryption and public keys paths.

    gpg_key_type: RSA
    gpg_key_length: 4096
    gpg_subkey_type: RSA
    gpg_subkey_length: 4096
    gpg_name_real: yourname
    gpg_name_email: youremail@yoremaildomain.com
    gpg_expiry_date: 0

GPG-specific configuration. These variables will be insterted into the GPG configuration tempalte (see templates/gpgconf.j2) to allow for unintended and fully automated GPG key generation.

Hardening:

    enable_harden = true

A task-level option for whether to run the harden task (see 'tasks/harden.yml).

## Dependencies

None.

## Example Ansible Playbook

    - hosts: all
      roles:
        - { role: misp }

## Example Ansible Playbook usage

    ```shell
    ansible-playbook misp.yml -i hosts
    ```

## Notes

* The Ansible Role was tested using Ansible 2.1.1.0.
* The Ansible Role uses the following templates: config.php.j2, bootstrap.php.j2, core.php.j2, database.php.j2 originally from the MISP Project, misp-ssl.conf.j2 for the Apache2 MISP site, and gpgconf.j2 for automated GPG key generation.
* The 'tasks/harden.yml' performs the simplist steps to limit exposures and is not meant to be a full hardening task.
* The Ansible Role will auto-generate a self-signed certificate based on the variables set in the SSL variables section.
* The Ansible Role will auto-generate GPG keys based on the variable set in the GPG variables section.
* The Ansible Role takes advantage of Ansible's Password Lookup module to auto-generate the 32 byte string and use the generated value as a fact. This behavior can be disabled in the Salt variables section.
* MISP default username/password: admin@admin.test/admin

## TODO

* Add Task to change the MySQL default root password in 'tasks/harden.yml'.
* Add supprt to setup MISP backup, see 'tools/misp-backup' in MISP's main repository.
