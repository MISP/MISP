# Migration guide to new Background Jobs backend
As of **MISP** version `2.4.151` we introduced a simpler way to handle background jobs without relying in CakeResque as this library is no longer maintained.

For the time being both background jobs backends will be supported, but we plan to phase out the CakeResque one in a near future.

The new backend requires [Supervisor](http://supervisord.org/) and some extra PHP packages.

**This guide is intended for Ubuntu/Debian and RHEL systems, make sure you execute the version for your distribution**

## Install requirements
Run on your MISP instance the following commands.

1. Install **Supervisord**:
    - Ubuntu / Debian
    ```
    sudo apt install supervisor -y
    ```
    - RHEL
    ```
    sudo dnf install -y supervisor
    ```


2. Install required PHP packages:
    - Ubuntu / Debian
    ```
    cd /var/www/MISP/app
    sudo -u www-data php composer.phar require --with-all-dependencies supervisorphp/supervisor:^4.0 \
        guzzlehttp/guzzle \
        php-http/message \
        php-http/message-factory \
        lstrojny/fxmlrpc
    ```
    - RHEL
    ```
    sudo -u apache sh -c "cd /var/www/MISP/app;php composer.phar require --with-all-dependencies supervisorphp/supervisor:^4.0 guzzlehttp/guzzle php-http/message php-http/message-factory lstrojny/fxmlrpc"
    ```

3. Add the following settings at the bottom of the **Supervisord** conf file, usually located in:

    - Ubuntu / Debian
    `/etc/supervisor/supervisord.conf`
    ```
    [inet_http_server]
    port=127.0.0.1:9001
    username=supervisor
    password=PWD_CHANGE_ME
    ```
   - RHEL (same content as above, just different config file path)
   `/etc/supervisord.conf`

4. Use the following configuration as a template for the services, usually located in:
    - Ubuntu / Debian
    `/etc/supervisor/conf.d/misp-workers.conf`
    ```
    [group:misp-workers]
    programs=default,email,cache,prio,update

    [program:default]
    directory=/var/www/MISP
    command=/var/www/MISP/app/Console/cake start_worker default
    process_name=%(program_name)s_%(process_num)02d
    numprocs=5
    autostart=true
    autorestart=true
    redirect_stderr=false
    stderr_logfile=/var/www/MISP/app/tmp/logs/misp-workers-errors.log
    stdout_logfile=/var/www/MISP/app/tmp/logs/misp-workers.log
    directory=/var/www/MISP
    user=www-data

    [program:prio]
    directory=/var/www/MISP
    command=/var/www/MISP/app/Console/cake start_worker prio
    process_name=%(program_name)s_%(process_num)02d
    numprocs=5
    autostart=true
    autorestart=true
    redirect_stderr=false
    stderr_logfile=/var/www/MISP/app/tmp/logs/misp-workers-errors.log
    stdout_logfile=/var/www/MISP/app/tmp/logs/misp-workers.log
    directory=/var/www/MISP
    user=www-data

    [program:email]
    directory=/var/www/MISP
    command=/var/www/MISP/app/Console/cake start_worker email
    process_name=%(program_name)s_%(process_num)02d
    numprocs=5
    autostart=true
    autorestart=true
    redirect_stderr=false
    stderr_logfile=/var/www/MISP/app/tmp/logs/misp-workers-errors.log
    stdout_logfile=/var/www/MISP/app/tmp/logs/misp-workers.log
    directory=/var/www/MISP
    user=www-data

    [program:update]
    directory=/var/www/MISP
    command=/var/www/MISP/app/Console/cake start_worker update
    process_name=%(program_name)s_%(process_num)02d
    numprocs=1
    autostart=true
    autorestart=true
    redirect_stderr=false
    stderr_logfile=/var/www/MISP/app/tmp/logs/misp-workers-errors.log
    stdout_logfile=/var/www/MISP/app/tmp/logs/misp-workers.log
    directory=/var/www/MISP
    user=www-data

    [program:cache]
    directory=/var/www/MISP
    command=/var/www/MISP/app/Console/cake start_worker cache
    process_name=%(program_name)s_%(process_num)02d
    numprocs=5
    autostart=true
    autorestart=true
    redirect_stderr=false
    stderr_logfile=/var/www/MISP/app/tmp/logs/misp-workers-errors.log
    stdout_logfile=/var/www/MISP/app/tmp/logs/misp-workers.log
    user=www-data
    ```
   - RHEL. Same file content as above except for user which should be apache, find and replace www-data -> apache. Filepath is also different, see below:
   `/etc/supervisord.d/misp-workers.ini`

## Make SELinux happy
***These steps are only relevant for systems with SELinux enabled (typically RHEL)!!!*** Create and install an SELinux module to run new misp-workers as httpd_t, this will make sure the workers diagnostics page works. If you get some message there saying you are not running the workers with correct user, so it can't get the status, SELinux is potentially the cause:

1. Install required packages
    ```
    sudo dnf install -y selinux-policy-devel setools-console
    ```
2. Create and move to temp dir where we will create the required files
    ```
    mkdir /tmp/misp-modules-supervisord
    cd /tmp/misp-modules-supervisord
    ```
3. Create file and add content to
   `misp-workers-httpd.te`
    ```
    policy_module(misp-workers-httpd, 1.0)
    require{
        type unconfined_service_t, httpd_sys_script_exec_t, httpd_t;
    }
    
    domtrans_pattern(unconfined_service_t, httpd_sys_script_exec_t, httpd_t);
    allow httpd_t httpd_sys_script_exec_t:file entrypoint;
    ```
4. Make and install module
    ```
    make -f /usr/share/selinux/devel/Makefile misp-workers-httpd.pp
    sudo semodule -i misp-workers-httpd.pp
    ```

5. Restart **Supervisord** to load the changes:
    ```
    sudo systemctl restart supervisord
    ```

## MISP Config
1. Go to your **MISP** instances `Server Settings & Maintenance` page, and then to the new [SimpleBackgroundJobs]((https://localhost/servers/serverSettings/SimpleBackgroundJobs)) tab.

2. Update the `SimpleBackgroundJobs.supervisor_password` with the password you set in the _Install requirements_ section 3.

3. Update the `SimpleBackgroundJobs.supervisor_user` with the supervisord username. (default: supervisor)

4. Verify Redis and other settings are correct and then set `SimpleBackgroundJobs.enabled` to `true`.

5. Restart **Supervisord** to load the changes:
    - Ubuntu / Debian
    ```
    sudo service supervisor restart
    ```
    - RHEL
    ```
    sudo systemctl restart supervisord
    ```

6. Check **Supervisord** workers are running:
    ```
    $ sudo supervisorctl status
    misp-workers:cache_00            RUNNING   pid 1673228, uptime 1:37:54
    misp-workers:cache_01            RUNNING   pid 1673225, uptime 1:37:54
    misp-workers:cache_02            RUNNING   pid 1673375, uptime 1:37:53
    misp-workers:cache_03            RUNNING   pid 1673398, uptime 1:37:52
    misp-workers:cache_04            RUNNING   pid 1673303, uptime 1:37:53
    misp-workers:default_00          RUNNING   pid 1673222, uptime 1:37:54
    misp-workers:default_01          RUNNING   pid 1673385, uptime 1:37:52
    misp-workers:default_02          RUNNING   pid 1673391, uptime 1:37:52
    misp-workers:default_03          RUNNING   pid 1673223, uptime 1:37:54
    misp-workers:default_04          RUNNING   pid 1673393, uptime 1:37:52
    misp-workers:email_00            RUNNING   pid 1673394, uptime 1:37:52
    misp-workers:email_01            RUNNING   pid 1673312, uptime 1:37:53
    misp-workers:email_02            RUNNING   pid 1673224, uptime 1:37:54
    misp-workers:email_03            RUNNING   pid 1673227, uptime 1:37:54
    misp-workers:email_04            RUNNING   pid 1673333, uptime 1:37:53
    misp-workers:prio_00             RUNNING   pid 1673279, uptime 1:37:54
    misp-workers:prio_01             RUNNING   pid 1673304, uptime 1:37:53
    misp-workers:prio_02             RUNNING   pid 1673305, uptime 1:37:53
    misp-workers:prio_03             RUNNING   pid 1673232, uptime 1:37:54
    misp-workers:prio_04             RUNNING   pid 1673319, uptime 1:37:53
    misp-workers:update_00           RUNNING   pid 1673327, uptime 1:37:53
    ```

7. Use **MISP** normally and visit [Administration -> Jobs](/jobs/index) to check Jobs are running correctly. 
    If there are any issues check the logs:
    * /var/www/MISP/app/tmp/logs/misp-workers-errors.log
    * /var/www/MISP/app/tmp/logs/misp-workers.log

8. Once the new workers are functioning as expected, you can remove the previous workers service:
    ```bash
    $ sudo systemctl stop --now misp-workers
    $ sudo systemctl disable --now misp-workers
    ```

### Notes
Scheduled tasks (TasksController) are not supported with the new backend, however this feature is going to be deprecated, it is recommended to use cron jobs instead.
