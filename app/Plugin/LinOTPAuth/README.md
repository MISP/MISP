# LinOTP Authentication Plugin

This plugin enables 2FA authentication against [LinOTP](https://linotp.org).
User logins are verified against LinOTP. Depending on the LinOTP configuration
additional credentials will be asked for.

For more information about configuring LinOTP see the [Management guide](https://www.linotp.org/doc/latest/part-management).

## Configuration

1. Enable the `LinOTPAuth` plugin in `app/config/bootstrap.php`
    The `bootstrap.default.php` contains a line similar to the line below.
    Uncomment it to load the Plugin.

    Change
        ```php
            // CakePlugin::load('LinOTPAuth');
        ```
    to
        ```php
            CakePlugin::load('LinOTPAuth');
        ```

2. Configure the plugin in `config.php`
    Add a `LinOTPAuth` section to your `config.php` as shown in
    `app/config/config.default.php`.
    ```php
       …
         'LinOTPAuth' => // Configuration for the LinOTP authentication
       	    array(
       	        'baseUrl' => 'https://linotp', // The base URL of LinOTP
       	        'realm' => 'lino', // the (default) realm of all the users logging in through this system
       	        'userModel' => 'User', // name of the User class (MISP class) to check if the user exists
                   'userModelKey' => 'email', // User field that will be used for querying.
               ),
       …
    ```

3. Add the module to the `Security.Auth` list.
   In `app/Config/config.php` within the `Security` array add another key
   `auth` with the value `array("LinOTPAuth.LinOTP")`.  The entire `Security`
   array might then look similar to the example displayed below.
   ```php
   	    'Security'         =>
            array(
                'level'      => 'medium',
                'salt'       => 'SOME SEED',
                'cipherSeed' => 'SOME OTHER SEED',
                'auth'=>array('LinOTPAUth.LinOTP'),
            ),
   ```

   Your MISP installation will most likely already have values on the `salt`
   and `cipherSeed` fields. Leave them as they are. The values displayed above
   are just placeholders.

4. Add users to LinOTP and then logon to MISP.
