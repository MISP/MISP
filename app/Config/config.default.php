<?php
$config = array(
    'debug' => 0,
    'Security' => array(
        'level'                             => 'medium',
        'salt'                              => '',
        'cipherSeed'                        => '',
        'require_password_confirmation'     => true,
        'auth_enforced'                     => false,
        'rest_client_baseurl'               => 'https://localhost',
        'advanced_authkeys'                 => true,
        'password_policy_length'            => 12,
        'password_policy_complexity'        => '/^((?=.*\\d)|(?=.*\\W+))(?![\\n])(?=.*[A-Z])(?=.*[a-z]).*$|.{16,}/',
        'self_registration_message'         => 'If you would like to send us a registration request, please fill out the form below. Make sure you fill out as much information as possible in order to ease the task of the administrators.',
        'allow_self_registration'           => false,
        'rest_client_enable_arbitrary_urls' => false,
        'user_monitoring_enabled'           => false,
        'authkey_keep_session'              => false,
        'disable_local_feed_access'         => false,
        'enable_svg_logos'                  => false,
        //'auth'                            => array('CertAuth.Certificate'), // additional authentication methods
        //'auth'                            => array('ShibbAuth.ApacheShibb'),
        //'auth'                            => array('AadAuth.AadAuthenticate'),
        //'auth'                            => array('LinOTPAuth.LinOTP'),
    ),
    'MISP' => array(
        'baseurl'                        => '',
        'footermidleft'                  => '',
        'footermidright'                 => '',
        'org'                            => 'ORGNAME',
        'showorg'                        => true,
        'threatlevel_in_email_subject'   => true,
        'email_subject_TLP_string'       => 'tlp:amber',
        'email_subject_tag'              => 'tlp',
        'email_subject_include_tag_name' => true,
        'background_jobs'                => true,
        'osuser'                         => 'www-data',
        'email'                          => 'email@example.com',
        'contact'                        => 'email@example.com',
        'cveurl'                         => 'https://cve.circl.lu/cve/',
        'cweurl'                         => 'https://cve.circl.lu/cwe/',
        'disablerestalert'               => false,
        'default_event_distribution'     => '1',
        'default_attribute_distribution' => 'event',
        'tagging'                        => true,
        'full_tags_on_event_index'       => true,
        'attribute_tagging'              => true,
        'full_tags_on_attribute_index'   => true,
        'footer_logo'                    => '',
        'take_ownership_xml_import'      => false,
        'unpublishedprivate'             => false,
        'disable_emailing'               => false,
        'manage_workers'                 => true,
        'python_bin'                     => null,
        'external_baseurl'               => '',
        'forceHTTPSforPreLoginRequestedURL' => false,
        'showCorrelationsOnIndex'        => true,
        'default_event_tag_collection'   => 0,
        'language'                       => 'eng',
        'proposals_block_attributes'     => false,
        'redis_host'                     => '127.0.0.1',
        'redis_port'                     => 6379,
        'redis_database'                 => 13,
        'redis_password'                 => '',
        'ssdeep_correlation_threshold'   => 40,
        'extended_alert_subject'         => false,
        'default_event_threat_level'     => '4',
        'newUserText'                    => 'Dear new MISP user,\\n\\nWe would hereby like to welcome you to the $org MISP community.\\n\\n Use the credentials below to log into MISP at $misp, where you will be prompted to manually change your password to something of your own choice.\\n\\nUsername: $username\\nPassword: $password\\n\\nIf you have any questions, don\'t hesitate to contact us at: $contact.\\n\\nBest regards,\\nYour $org MISP support team',
        'passwordResetText'              => 'Dear MISP user,\\n\\nA password reset has been triggered for your account. Use the below provided temporary password to log into MISP at $misp, here you will be prompted to manually change your password to something of your own choice.\\n\\nUsername: $username\\nYour temporary password: $password\\n\\nIf you have any questions, don\'t hesitate to contact us at: $contact.\\n\\nBest regards,\\n Your $org MISP support team',
        'enableEventBlocklisting'        => true,
        'enableOrgBlocklisting'          => true,
        'log_client_ip'                  => false,
        'log_auth'                       => false,
        'store_api_access_time'          => false,
        'disableUserSelfManagement'      => false,
        'disable_user_login_change'      => false,
        'disable_user_password_change'   => false,
        'disable_user_add'               => false,
        'block_event_alert'              => false,
        'block_event_alert_tag'          => 'no-alerts="true"',
        'block_old_event_alert'          => false,
        'block_old_event_alert_age'      => 0,
        'block_old_event_alert_by_date'  => 0,
        'incoming_tags_disabled_by_default' => false,
        'maintenance_message'            => 'Great things are happening! MISP is undergoing maintenance, but will return shortly. You can contact the administration at $email.',
        'welcome_text_top'               => 'Initial Install, please configure',
        'welcome_text_bottom'            => '',
        'attachments_dir'                => null,
        'download_attachments_on_load'   => true,
        'title_text'                     => 'MISP',
        'terms_download'                 => false,
        'showorgalternate'               => false,
        'event_view_filter_fields'       => 'id, uuid, value, comment, type, category, Tag.name',
        'live'                           => true,
        'uuid'                           => '',
        'delegation'                     => true,
        'max_correlations_per_event'     => 5000,
        'disable_auto_logout'            => false,
        'log_paranoid_skip_db'           => false,
        'log_paranoid'                   => false,
        'log_user_ips'                   => false,
        'event_alert_republish_ban'      => true,
        'event_alert_republish_ban_threshold' => 120,
        'event_alert_republish_ban_refresh_on_retry' => true,
        'user_email_notification_ban'      => true,
        'user_email_notification_ban_time_threshold' => 120,
        'user_email_notification_ban_amount_threshold' => 10,
        'user_email_notification_ban_refresh_on_retry' => true,
        'warning_for_all'                => false,
        'enable_synchronisation_filtering_on_type' => false,
    ),
    'GnuPG' => array(
        'onlyencrypted'     => false,
        'email'             => '',
        'homedir'           => '',
        'password'          => '',
        'bodyonlyencrypted' => false,
        'sign'              => true,
        'obscure_subject'   => false,
        'binary'            => '/usr/bin/gpg'
    ),
    'SMIME' => array(
        'enabled'          => false,
        'email'            => '',
        'cert_public_sign' => '',
        'key_sign'         => '',
        'password'         => '',
    ),
    'Proxy' => array(
        'host'     => '',
        'port'     => '',
        'method'   => '',
        'user'     => '',
        'password' => '',
    ),
    'SecureAuth' => array(
        'amount' => 5,
        'expire' => 300,
    ),
    'SimpleBackgroundJobs' => array(
        'enabled' => false,
        'redis_host' => 'localhost',
        'redis_port' => 6379,
        'redis_password' => '',
        'redis_database' => 1,
        'redis_namespace' => 'background_jobs',
        'max_job_history_ttl' => 86400,
        'supervisor_host' => 'localhost',
        'supervisor_port' => 9001,
        'supervisor_user' => 'supervisor',
        'supervisor_password' => '',
    ),
    // Uncomment the following to enable client SSL certificate authentication
    /*
    'CertAuth'         => array(

        // CA
        'ca'           => array('FIRST.Org'), // List of CAs authorized
        'caId'         => 'O',          // Certificate field used to verify the CA. In this example, the field O (organization) of the client certificate has to equal to 'FIRST.Org' in order to validate the CA

        // User/client configuration
        'userModel'    => 'User',       // name of the User class (MISP class) to check if the user exists
        'userModelKey' => 'email',      // User field that will be used for querying. In this example, the field email of the MISP accounts will be used to search if the user exists.
        'map'          => array(        // maps client certificate attributes to User properties. This map will be used as conditions to find if the user exists. In this example, the client certificate fields 'O' (organization) and 'emailAddress' have to match with the MISP fields 'org' and 'email' to validate the user.
            'O'            => 'org',
            'emailAddress' => 'email',
        ),

        // Synchronization/RestAPI
        'syncUser'     => true,         // should the User be synchronized with an external REST API
        'userDefaults' => array(          // default user attributes, only used when creating new users. By default, new users are "Read only" users (role_id: 6).
            'role_id' => 6,
        ),
        'restApi'      => array(        // API parameters
            'url'     => 'https://example.com/data/users',  // URL to query
            'headers' => array(),                           // additional headers, used for authentication
            'param'   => array('email' => 'email'),       // query parameters to add to the URL, mapped to User properties
            'map'     => array(                            // maps REST result to the User properties
                'uid'        => 'nids_sid',
                'team'       => 'org',
                'email'      => 'email',
                'pgp_public' => 'gpgkey',
            ),
        ),
        'userDefaults' => array('role_id' => 6),          // default attributes for new users. By default, new users are "Read only" users (role_id: 6).
    ),
    */
    /*
    'ApacheShibbAuth'  => array(                     // Configuration for shibboleth authentication
        'apacheEnv'         => 'REMOTE_USER',        // If proxy variable = HTTP_REMOTE_USER
        'MailTag'           => 'EMAIL_TAG',
        'OrgTag'            => 'FEDERATION_TAG',
        'GroupTag'          => 'GROUP_TAG',
        'GroupSeparator'    => ';',
        'GroupRoleMatching' => array(                // 3:User, 1:admin. May be good to set "1" for the first user
            'group_three' => 3,
            'group_two'   => 2,
            'group_one'   => 1,
        ),
        'DefaultOrg'        => 'DEFAULT_ORG',
    ),
    */
    /*
    'LinOTPAuth' => array( // Configuration for the LinOTP authentication
        'baseUrl' => 'https://linotp', // The base URL of LinOTP
        'realm' => 'lino', // the (default) realm of all the users logging in through this system
        'userModel' => 'User', // name of the User class (MISP class) to check if the user exists
        'userModelKey' => 'email', // User field that will be used for querying.
        'verifyssl' => true, // Verify TLS Certificate or not
        'mixedauth' => false, // false=>Query only LinOTP or true=>OTP from LinOTP, Password from MISP
    ),
    */
    // Warning: The following is a 3rd party contribution and still untested (including security) by the MISP-project team.
    // Feel free to enable it and report back to us if you run into any issues.
    //
    // Uncomment the following to enable Kerberos/LDAP authentication
    // needs PHP LDAP support enabled (e.g. compile flag --with-ldap or Debian package php5-ldap)
    /*
    'ApacheSecureAuth' => array( // Configuration for kerberos/LDAP authentication
        'apacheEnv'          => 'REMOTE_USER',           // If proxy variable = HTTP_REMOTE_USER, If BasicAuth ldap = PHP_AUTH_USER
        'ldapServer'         => 'ldap://example.com',   // FQDN or IP, ldap:// for LDAP or LDAP+STARTTLS, ldaps:// for LDAPS
        'starttls'           => true, // true for STARTTLS, ignored for LDAPS
        'ldapProtocol'       => 3,
        'ldapNetworkTimeout' => -1,  // use -1 for unlimited network timeout
        'ldapReaderUser'     => 'cn=userWithReadAccess,ou=users,dc=example,dc=com', // DN ou RDN LDAP with reader user right
        'ldapReaderPassword' => 'UserPassword', // the LDAP reader user password
        'ldapDN'             => 'dc=example,dc=com',
        'ldapSearchFilter'   => '', // Search filter to limit results from ldapsearh fx to specific group. FX
        //'ldapSearchFilter'   => '(objectclass=InetOrgPerson)(!(nsaccountlock=True))(memberOf=cn=misp,cn=groups,cn=accounts,dc=example,dc=com)',
        'ldapSearchAttribut' => 'uid',          // filter for search
        'ldapFilter'         => array(
            'mail',
            //	'memberOf', //Needed filter if roles should be added depending on group membership.
        ),
        'ldapDefaultRoleId'  => 3,               // 3:User, 1:admin. May be good to set "1" for the first user
        //ldapDefaultRoleId can also be set as an array to support creating users into different group, depending on ldap membership.
        //This will only work if the ldap server supports memberOf
        //'ldapDefaultRoleId'  => array(
            //                         'misp_admin' => 1,
            //                         'misp_orgadmin' => 2,
            //                         'misp_user' => 3,
            //                         'misp_publisher' => 4,
            //                         'misp_syncuser' => 5,
            //                         'misp_readonly' => 6,
            //                         ),
            //
        'ldapDefaultOrg'     => '1',      // uses 1st local org in MISP if undefined,
        'ldapAllowReferrals' => true,   // allow or disallow chasing LDAP referrals
        //'ldapEmailField' => array('emailAddress, 'mail'), // Optional : fields from which the email address should be retrieved. Default to 'mail' only. If more than one field is set (e.g. 'emailAddress' and 'mail' in this example), only the first one will be used.
        //'updateUser' => true, // Optional : Will update user on LDAP login to update user fields (e.g. role)
    ),
    */

    // Warning: The following is a 3rd party contribution and still untested (including security) by the MISP-project team.
    // Feel free to enable it and report back to us if you run into any issues.
    //
    // Uncomment the following to enable Azure AD authentication
    /*
    'AadAuth' => array(
        'client_id' => '', // Client ID (see Azure AD)
        'ad_tenant' => '', // Directory ID (see Azure AD)
        'client_secret' => '', // Client secret (see Azure AD)
        'redirect_uri' => '', // Your MISP URI, must be the same as in Azure AD
        'auth_provider' => 'https://login.microsoftonline.com/',	// Can be left to this default
        'auth_provider_user' => 'https://graph.microsoft.com/',		// Can be left to this default
        'misp_user' => 'MISP Users',	// The AD group for MISP users
        'misp_orgadmin' => 'MISP Administrators',	// The AD group for MISP administrators
        'misp_siteadmin' => 'MISP Site Administrators', 	// The AD group for MISP site administrators
        'check_ad_groups' => true	// Should we check if the user belongs to one of the above AD groups?
    ),
    */
);
