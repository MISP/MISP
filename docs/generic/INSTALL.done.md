!!! warning
    If you have installed the recommended Python 3 virtualenv to the recommended place of **${PATH_TO_MISP}/venv** set the following MISP configurable
    ```bash
    sudo -H -u www-data $CAKE Admin setSetting "MISP.python_bin" "${PATH_TO_MISP}/venv/bin/python"
    ```
    or on Rocky Linux
    ```bash
    sudo -u apache $RUN_PHP "$CAKE Admin setSetting "MISP.python_bin" "${PATH_TO_MISP}/venv/bin/python""
    ```

!!! warning
    Make sure that the STIX libraries and GnuPG work as intended, if not, refer to the relevant sections in the install guide you are currently reading.

!!! notice
    Now log in using the webinterface: http://misp/users/login<br />
    The default user/pass = admin@admin.test/admin<br />
    Using the server settings tool in the admin interface (Administration -> Server Settings), set MISP up to your preference.<br />
    It is especially vital that no critical issues remain!<br />
    Don't forget to change the email, password and authentication key after installation.<br />
    Once done, have a look at the diagnostics.

!!! notice
    If any of the directories that MISP uses to store files is not writeable to the apache user, change the permissions<br />
    you can do this by running the following commands:
    ```bash
    chmod -R 750 ${PATH_TO_MISP}/<directory path with an indicated issue>
    # /!\ Depending on your OS replace www-data with apache or www or whatever user is the web server user.
    chown -R www-data:www-data ${PATH_TO_MISP}/<directory path with an indicated issue>
    ```

!!! notice
    If anything goes wrong, make sure that you check MISP's logs for errors:
    ```
    # ${PATH_TO_MISP}/app/tmp/logs/error.log
    # ${PATH_TO_MISP}/app/tmp/logs/resque-worker-error.log
    # ${PATH_TO_MISP}/app/tmp/logs/resque-scheduler-error.log
    # ${PATH_TO_MISP}/app/tmp/logs/resque-2018-10-25.log //where the actual date is the current date
    ```
