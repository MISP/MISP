<?php

App::uses('BaseAuthenticate', 'Controller/Component/Auth');

class LdapAuthenticate extends BaseAuthenticate
{

    /**
     * Holds the user information
     *
     * @var array
     */
    protected static $user = false;

    protected static $conf;

    // Active Directory's LDAP_MATCHING_RULE_IN_CHAIN. Applied to `member`, it
    // matches groups reached through nested groups as well as direct ones.
    // AD-specific: other directories treat it as an unknown matching rule.
    const LDAP_MATCHING_RULE_IN_CHAIN = '1.2.840.113556.1.4.1941';

    // ADS_UF_ACCOUNTDISABLE, the ACCOUNTDISABLE bit of userAccountControl.
    const ADS_UF_ACCOUNTDISABLE = 2;

    /* 
    'LdapAuth' => [
        'ldapServer' => 'ldap://openldap:1389',
        'ldapDn' => 'dc=example,dc=com',
        'ldapReaderUser' => 'cn=reader,dc=example,dc=com',
        'ldapReaderPassword' => 'password'
    ]
    */

    public function __construct()
    {
        self::$conf = [
            'ldapServer' => Configure::read('LdapAuth.ldapServer'),
            'ldapDn' => Configure::read('LdapAuth.ldapDn'),
            'ldapReaderUser' => Configure::read('LdapAuth.ldapReaderUser'),
            'ldapReaderPassword' => Configure::read('LdapAuth.ldapReaderPassword'),
            'ldapSearchFilter' => Configure::read('LdapAuth.ldapSearchFilter') ?? '',
            'ldapSearchAttribute' => Configure::read('LdapAuth.ldapSearchAttribute') ?? 'mail',
            'ldapEmailField' => Configure::read('LdapAuth.ldapEmailField') ?? ['mail'],
            'ldapNetworkTimeout' => Configure::read('LdapAuth.ldapNetworkTimeout') ?? -1,
            'ldapProtocol' => Configure::read('LdapAuth.ldapProtocol') ?? 3,
            'ldapAllowReferrals' => Configure::read('LdapAuth.ldapAllowReferrals') ?? true,
            'starttls' => Configure::read('LdapAuth.starttls') ?? false,
            'mixedAuth' => Configure::read('LdapAuth.mixedAuth') ?? true,
            'ldapDefaultOrgId' => Configure::read('LdapAuth.ldapDefaultOrgId') ?? 1,
            'ldapOrgField' => Configure::read('LdapAuth.ldapOrgField') ?? null,
            'ldapOrgGroupMapping' => Configure::read('LdapAuth.ldapOrgGroupMapping') ?? null,
            'ldapDefaultRoleId' => Configure::read('LdapAuth.ldapDefaultRoleId') ?? 3,
            'ldapRoleField' => Configure::read('LdapAuth.ldapRoleField') ?? null,
            'ldapRoleGroupMapping' => Configure::read('LdapAuth.ldapRoleGroupMapping') ?? null,
            'updateUser' => Configure::read('LdapAuth.updateUser') ?? true,
            'debug' => Configure::read('LdapAuth.debug') ?? false,
            'ldapTlsRequireCert' => Configure::read('LdapAuth.ldapTlsRequireCert') ?? LDAP_OPT_X_TLS_DEMAND,
            'ldapTlsCustomCaCert' => Configure::read('LdapAuth.ldapTlsCustomCaCert') ?? false,
            'ldapTlsCrlCheck' => Configure::read('LdapAuth.ldapTlsCrlCheck') ?? LDAP_OPT_X_TLS_CRL_PEER,
            'ldapTlsProtocolMin' => Configure::read('LdapAuth.ldapTlsProtocolMin') ?? LDAP_OPT_X_TLS_PROTOCOL_TLS1_2,
            'ldapEscape' => Configure::read('LdapAuth.ldapEscape') ?? false,
            'ldapEscapeIgnoreChars' => Configure::read('LdapAuth.ldapEscapeIgnoreChars') ?? "",
            'ldapUseMemberOf' => Configure::read('LdapAuth.ldapUseMemberOf') ?? false,
            'ldapNestedGroups' => Configure::read('LdapAuth.ldapNestedGroups') ?? false,
            'ldapCheckUserAccountControl' => Configure::read('LdapAuth.ldapCheckUserAccountControl') ?? false,
        ];

        if (self::$conf['ldapEscape'] && self::$conf['ldapSearchFilter']) {
            self::$conf['ldapSearchFilter'] = ldap_escape(self::$conf['ldapSearchFilter'], self::$conf['ldapEscapeIgnoreChars'], LDAP_ESCAPE_FILTER);
        }
    }

    public function authenticate(CakeRequest $request, CakeResponse $response)
    {
        // Try to authenticate the incoming request against the LDAP backend
        $user = $this->getUser($request);

        return $user;
    }

    private function ldapConnect()
    {
        if (self::$conf['debug']) {
            ldap_set_option(null, LDAP_OPT_DEBUG_LEVEL, 7);
        }

        // LDAP connection
        ldap_set_option(NULL, LDAP_OPT_NETWORK_TIMEOUT, self::$conf['ldapNetworkTimeout']);

        // SSL/TLS configuration
        if (self::$conf['ldapTlsCustomCaCert']) {
            ldap_set_option(null, LDAP_OPT_X_TLS_CACERTDIR, dirname(self::$conf['ldapTlsCustomCaCert']));
            ldap_set_option(null, LDAP_OPT_X_TLS_CACERTFILE, self::$conf['ldapTlsCustomCaCert']);
        }

        ldap_set_option(null, LDAP_OPT_X_TLS_REQUIRE_CERT, self::$conf['ldapTlsRequireCert']);
        ldap_set_option(null, LDAP_OPT_X_TLS_CRLCHECK, self::$conf['ldapTlsCrlCheck']);
        ldap_set_option(null, LDAP_OPT_X_TLS_PROTOCOL_MIN, self::$conf['ldapTlsProtocolMin']);

        // Connect to LDAP server
        $ldapconn = ldap_connect(self::$conf['ldapServer']);

        if (!$ldapconn) {
            CakeLog::error("[LdapAuth] LDAP server connection failed.");
            throw new UnauthorizedException(__('User could not be authenticated by LDAP.'));
        }

        // LDAP protocol configuration
        ldap_set_option($ldapconn, LDAP_OPT_PROTOCOL_VERSION, self::$conf['ldapProtocol']);
        ldap_set_option($ldapconn, LDAP_OPT_REFERRALS, self::$conf['ldapAllowReferrals']);

        if (self::$conf['starttls'] == true) {
            # Default is false, sine STARTTLS support is a new feature
            # Ignored on ldaps://, but can trigger problems for orgs
            # using unencrypted LDAP. Loose comparison allows users to
            # use # true / 1 / etc.
            ldap_start_tls($ldapconn);
        }

        return $ldapconn;
    }

    private function getEmailAddress($ldapEmailField, $ldapUserData)
    {
        // return the email address of an LDAP user if one of the fields in $ldapEmailField exists
        return $this->getFirstAttributeValue($ldapEmailField, $ldapUserData);
    }

    // Returns the value of the first attribute in $fields that the entry
    // carries, or null. Shared by every setting that names an attribute, so
    // they all agree on how entries are read.
    private function getFirstAttributeValue($fields, $ldapUserData)
    {
        $entry = isset($ldapUserData[0]) ? $ldapUserData[0] : [];
        foreach ((array)$fields as $field) {
            // ldap_get_entries() lowercases attribute names, so a field
            // configured the way it is spelled in the schema, such as
            // `userPrincipalName`, would never match a literal lookup.
            $key = strtolower($field);
            if (!isset($entry[$key])) {
                continue;
            }

            $value = $entry[$key];
            if (is_array($value)) {
                // Regular attributes arrive as ['count' => n, 0 => ..., ...].
                if (isset($value[0])) {
                    return $value[0];
                }
                continue;
            }

            // `dn` is the exception: it comes back as a plain string, so
            // indexing it would yield its first character rather than the
            // distinguished name -- which silently collapsed every user onto
            // a single account.
            if ($value !== '') {
                return $value;
            }
        }
        return null;
    }

    // Looks up one organisation by id or by name.
    //
    // An all-digit value is read as an organisation id, anything else as an
    // organisation name, so either can be published by the directory.
    private function findOrganisationId($userModel, $value)
    {
        $conditions = ctype_digit((string)$value)
            ? ['Organisation.id' => (int)$value]
            : ['Organisation.name' => $value];

        $organisation = $userModel->Organisation->find(
            'first',
            [
                'conditions' => $conditions,
                'fields' => ['Organisation.id'],
                'recursive' => -1
            ]
        );

        return empty($organisation) ? null : $organisation['Organisation']['id'];
    }

    // Resolves the MISP organisation for an LDAP user.
    //
    // `ldapOrgField` names an attribute on the user's entry holding an
    // organisation id or name. `ldapOrgGroupMapping` maps group memberships to
    // organisations, using the same memberships the role mapping reads: keys
    // are group CNs, or full group DNs when `ldapUseMemberOf` is enabled. With
    // both configured the attribute is tried first, then the groups, so the
    // two compose for directories that express the organisation either way.
    //
    // `ldapDefaultOrgId` applies only when NEITHER is configured. Once the
    // organisation is meant to come from the directory, a user it cannot be
    // resolved for is refused rather than quietly placed in the default
    // organisation: an organisation is a sharing boundary in MISP, and
    // defaulting into it would widen someone's access on the strength of
    // missing data.
    private function getOrganisationId($userModel, $ldapUserData, $groups = [])
    {
        $usesOrgField = !empty(self::$conf['ldapOrgField']);
        $usesGroupMapping = !empty(self::$conf['ldapOrgGroupMapping']);

        if (!$usesOrgField && !$usesGroupMapping) {
            return self::$conf['ldapDefaultOrgId'];
        }

        if ($usesOrgField) {
            $value = $this->getFirstAttributeValue(self::$conf['ldapOrgField'], $ldapUserData);
            if ($value === null || $value === '') {
                CakeLog::warning(
                    "[LdapAuth] No organisation attribute on the LDAP entry."
                );
            } else {
                $orgId = $this->findOrganisationId($userModel, $value);
                if ($orgId !== null) {
                    return $orgId;
                }
                CakeLog::warning("[LdapAuth] No MISP organisation matches '$value'.");
            }
        }

        if ($usesGroupMapping) {
            foreach ($groups as $group) {
                if (!isset(self::$conf['ldapOrgGroupMapping'][$group])) {
                    continue;
                }
                $value = self::$conf['ldapOrgGroupMapping'][$group];
                $orgId = $this->findOrganisationId($userModel, $value);
                if ($orgId !== null) {
                    return $orgId;
                }
                CakeLog::warning(
                    "[LdapAuth] Group '$group' maps to organisation '$value', which MISP does not have."
                );
            }
            CakeLog::warning(
                "[LdapAuth] No group maps to an organisation for this user."
            );
        }

        CakeLog::error(
            "[LdapAuth] Could not resolve an organisation from LDAP, refusing login."
        );
        throw new UnauthorizedException(__('User could not be authenticated by LDAP.'));
    }

    // Looks up one role by id or by name, the same way organisations resolve.
    private function findRoleId($userModel, $value)
    {
        $conditions = ctype_digit((string)$value)
            ? ['Role.id' => (int)$value]
            : ['Role.name' => $value];

        $role = $userModel->Role->find(
            'first',
            [
                'conditions' => $conditions,
                'fields' => ['Role.id'],
                'recursive' => -1
            ]
        );

        return empty($role) ? null : $role['Role']['id'];
    }

    // The group -> role map in force, if any.
    //
    // `ldapDefaultRoleId` has always accepted an array to mean exactly this,
    // so that spelling keeps working and is treated as an alias of
    // `ldapRoleGroupMapping`, which takes precedence when both are given.
    private function getRoleGroupMapping()
    {
        if (!empty(self::$conf['ldapRoleGroupMapping'])) {
            return self::$conf['ldapRoleGroupMapping'];
        }
        if (is_array(self::$conf['ldapDefaultRoleId'])) {
            return self::$conf['ldapDefaultRoleId'];
        }
        return null;
    }

    // Whether the role mapping is walked in the order it is written.
    //
    // `ldapRoleGroupMapping` is, so a user in several mapped groups lands in
    // the role listed first and the config alone tells you which. The array
    // form of `ldapDefaultRoleId` predates that and is left walking the user's
    // memberships in whatever order the directory returned them, so upgrading
    // does not silently move anyone between roles.
    private function roleGroupMappingUsesSettingsOrder()
    {
        return !empty(self::$conf['ldapRoleGroupMapping']);
    }

    // Resolves the MISP role for an LDAP user, mirroring how the organisation
    // is resolved: `ldapRoleField` names an attribute on the user's entry
    // holding a role id or name, `ldapRoleGroupMapping` maps group
    // memberships to roles, and the attribute is tried first so the two
    // compose.
    //
    // `ldapDefaultRoleId` applies only when NEITHER is configured. Returns
    // null when the directory was supposed to decide and did not, which the
    // caller turns into a refused login rather than a default role: handing
    // out `ldapDefaultRoleId` on missing data would grant permissions nobody
    // asked for.
    private function getRoleId($userModel, $ldapUserData, $groups = [])
    {
        $groupMapping = $this->getRoleGroupMapping();
        $usesRoleField = !empty(self::$conf['ldapRoleField']);
        $usesGroupMapping = !empty($groupMapping);

        if (!$usesRoleField && !$usesGroupMapping) {
            return self::$conf['ldapDefaultRoleId'];
        }

        if ($usesRoleField) {
            $value = $this->getFirstAttributeValue(self::$conf['ldapRoleField'], $ldapUserData);
            if ($value === null || $value === '') {
                CakeLog::warning("[LdapAuth] No role attribute on the LDAP entry.");
            } else {
                $roleId = $this->findRoleId($userModel, $value);
                if ($roleId !== null) {
                    return $roleId;
                }
                CakeLog::warning("[LdapAuth] No MISP role matches '$value'.");
            }
        }

        if ($usesGroupMapping) {
            // Which sequence decides precedence for someone in several mapped
            // groups. Walking the mapping makes the config the answer; walking
            // the memberships leaves it to the directory's result order, which
            // is what the older ldapDefaultRoleId array form did.
            $candidates = $this->roleGroupMappingUsesSettingsOrder()
                ? array_keys($groupMapping)
                : $groups;
            $memberships = array_flip($groups);

            foreach ($candidates as $group) {
                if (!isset($groupMapping[$group]) || !isset($memberships[$group])) {
                    continue;
                }
                $value = $groupMapping[$group];
                $roleId = $this->findRoleId($userModel, $value);
                if ($roleId !== null) {
                    return $roleId;
                }
                CakeLog::warning(
                    "[LdapAuth] Group '$group' maps to role '$value', which MISP does not have."
                );
            }
            CakeLog::warning("[LdapAuth] No group maps to a role for this user.");
        }

        return null;
    }

    // True when Active Directory's userAccountControl has ACCOUNTDISABLE set.
    //
    // The attribute is a bit field, not an enumeration: an ordinary enabled
    // account reads 512 and the same account disabled reads 514, so this has
    // to mask the flag rather than compare for equality. Directories that do
    // not publish the attribute simply never match.
    private function isDirectoryAccountDisabled($ldapUserData)
    {
        if (!self::$conf['ldapCheckUserAccountControl']) {
            return false;
        }

        $value = $this->getFirstAttributeValue(['userAccountControl'], $ldapUserData);
        if ($value === null || !ctype_digit((string)$value)) {
            return false;
        }

        return ((int)$value & self::ADS_UF_ACCOUNTDISABLE) === self::ADS_UF_ACCOUNTDISABLE;
    }

    private function getUserMemberships($ldapconn, $ldapUserData)
    {
        $nested = self::$conf['ldapNestedGroups'];

        if (self::$conf['ldapUseMemberOf']) {
            if (!$nested) {
                return $this->getUserMembershipsFromMemberOf($ldapconn, $ldapUserData);
            }
            // `memberOf` cannot answer this: Active Directory keeps it
            // direct-only, so nesting has to be resolved from the group side.
            // Say so rather than quietly picking one of the two settings.
            CakeLog::warning(
                "[LdapAuth] ldapNestedGroups overrides ldapUseMemberOf; groups are searched under ldapDn, which must therefore contain them."
            );
        }

        $groups = [];
        $userDn = $ldapUserData[0]['dn'];
        if (self::$conf['ldapEscape']) {
            $userDn = ldap_escape($userDn, self::$conf['ldapEscapeIgnoreChars'], LDAP_ESCAPE_FILTER);
        }

        // With nesting on, match through the chain of nested groups instead of
        // only those listing the user directly.
        $attribute = $nested ? 'member:' . self::LDAP_MATCHING_RULE_IN_CHAIN . ':' : 'member';
        $filter = '(' . $attribute . '=' . $userDn . ')';
        $ldapUserMemberships = ldap_search($ldapconn, self::$conf['ldapDn'], $filter, ['cn']);

        if ($ldapUserMemberships) {
            $entries = ldap_get_entries($ldapconn, $ldapUserMemberships);
            foreach ($entries as $entry) {
                if (is_array($entry) && isset($entry[0])) {
                    $groups[] = $entry['cn'][0];
                }
            }
        }

        if ($nested && empty($groups)) {
            // Directories other than AD do not implement the matching rule and
            // answer an extensible match they do not know with success and no
            // entries, so this is indistinguishable from genuinely having no
            // groups. Flag it, otherwise the setting looks like it did nothing.
            CakeLog::warning(
                "[LdapAuth] No groups resolved with ldapNestedGroups enabled. If this directory is not Active Directory it likely ignores the matching rule " . self::LDAP_MATCHING_RULE_IN_CHAIN . ", which yields an empty result rather than an error."
            );
        }

        return $groups;
    }

    // Reads the user's `memberOf` attribute directly (AD-style lookup).
    // Returns full group DNs, so ldapDefaultRoleId keys must be DNs when this path is enabled.
    private function getUserMembershipsFromMemberOf($ldapconn, $ldapUserData)
    {
        $groups = [];
        $userDn = $ldapUserData[0]['dn'];
        $result = ldap_read($ldapconn, $userDn, '(objectClass=*)', ['memberOf']);
        if (!$result) {
            CakeLog::error("[LdapAuth] LDAP memberOf read failed: " . ldap_error($ldapconn));
            return $groups;
        }

        $entries = ldap_get_entries($ldapconn, $result);
        if (empty($entries[0]['memberof']['count'])) {
            return $groups;
        }

        for ($i = 0; $i < $entries[0]['memberof']['count']; $i++) {
            $groups[] = $entries[0]['memberof'][$i];
        }
        return $groups;
    }

    private function disableUser($mispUsername)
    {
        $userModel = ClassRegistry::init($this->settings['userModel']);
        $user = $this->_findUser($mispUsername);
        $user['disabled'] = 1;
        $userModel->save($user, false);
    }

    private function getLdapUserData($ldapconn, $email)
    {
        // LDAP search filter
        $email = ldap_escape($email, '', LDAP_ESCAPE_FILTER);
        $filter = '(' . self::$conf['ldapSearchAttribute'] . '=' . $email . ')';
        if (!empty(self::$conf['ldapSearchFilter'])) {
            $filter =  '(&' . self::$conf['ldapSearchFilter'] . $filter . ')';
        }

        // Only the attributes asked for here come back, so every setting that
        // names one has to be listed or it silently reads as absent.
        $attributes = (array)self::$conf['ldapEmailField'];
        foreach (['ldapOrgField', 'ldapRoleField'] as $setting) {
            if (!empty(self::$conf[$setting])) {
                $attributes = array_merge($attributes, (array)self::$conf[$setting]);
            }
        }
        if (self::$conf['ldapCheckUserAccountControl']) {
            // Only requested attributes come back, and without this one a
            // disabled Active Directory account would look enabled.
            $attributes[] = 'userAccountControl';
        }

        $ldapUser = ldap_search($ldapconn, self::$conf['ldapDn'], $filter, $attributes);

        if (!$ldapUser) {
            CakeLog::error("[LdapAuth] LDAP user search failed: " . ldap_error($ldapconn));
            throw new UnauthorizedException(__('User could not be authenticated by LDAP.'));
        }

        # Get user data
        $ldapUserData = ldap_get_entries($ldapconn, $ldapUser);
        if (!$ldapUserData) {
            CakeLog::error("[LdapAuth] LDAP get user entries failed: " . ldap_error($ldapconn));
            throw new UnauthorizedException(__('User could not be authenticated by LDAP.'));
        }

        return $ldapUserData;
    }

    /*
     * Retrieve a user by validating the request data
     */
    public function getUser($request)
    {
        if (!array_key_exists("User", $request->data)) {
            return false;
        }

        $userFields = $request->data['User'];
        // Read defensively: a request that simply omits `password` would
        // otherwise reach ldap_bind() as null, which is the same as sending
        // an empty one.
        $email = isset($userFields['email']) ? $userFields['email'] : '';
        $password = isset($userFields['password']) ? $userFields['password'] : '';

        CakeLog::debug("[LdapAuth] Login attempt with email: $email");
        $this->settings['fields'] = ["username" => "email"];

        // An empty password turns ldap_bind() into an *unauthenticated* bind,
        // which the LDAP protocol defines as a success for any existing DN.
        // Directories that do not refuse those (RFC 4513 leaves it to the
        // server) would hand out a session for any account whose identifier
        // is known. No MISP account has an empty password either, so refuse
        // here rather than relying on the directory to do it.
        if (!is_string($password) || $password === '') {
            CakeLog::error("[LdapAuth] Empty password for '$email', refusing the login attempt.");
            return false;
        }

        $ldapconn = $this->ldapConnect();

        $ldapbind = ldap_bind($ldapconn, self::$conf['ldapReaderUser'],  self::$conf['ldapReaderPassword']);
        if (!$ldapbind) {
            CakeLog::error("[LdapAuth] Invalid LDAP reader user credentials: " . ldap_error($ldapconn));
            throw new UnauthorizedException(__('User could not be authenticated by LDAP.'));
        }

        $ldapUserData = $this->getLdapUserData($ldapconn, $email);

        if ($ldapUserData['count'] == 0) {
            // If the user is not found in LDAP, try to authenticate against the local database if `mixedAuth` is enabled
            if (self::$conf['mixedAuth'] == true) {
                $this->settings['fields'] += ["password" => "password"];
                $this->settings['passwordHasher'] = "BlowfishConstant";
                return $this->_findUser($email, $password);
            } else {
                CakeLog::error("[LdapAuth] User not found in LDAP.");
                throw new UnauthorizedException(__('User could not be authenticated by LDAP.'));
            }
        }

        // Mirror an account Active Directory has disabled.
        //
        // Checked against the directory entry rather than the bind result on
        // purpose: AD refuses the bind for a disabled account, so waiting for
        // that would never tell us why and would leave the MISP account
        // enabled. Doing it here means the local account is revoked the next
        // time that person tries to log in.
        if ($this->isDirectoryAccountDisabled($ldapUserData)) {
            $disabledUsername = $this->getEmailAddress(self::$conf['ldapEmailField'], $ldapUserData);
            if (!empty($disabledUsername) && $this->_findUser($disabledUsername)) {
                CakeLog::debug("[LdapAuth] Account disabled in LDAP, disabling MISP user '$disabledUsername'.");
                $this->disableUser($disabledUsername);
            }
            CakeLog::error(
                "[LdapAuth] userAccountControl marks '$email' as disabled, refusing login."
            );
            throw new UnauthorizedException(__('User could not be authenticated by LDAP.'));
        }

        // Try to log-in with user LDAP password
        $ldapbind = ldap_bind($ldapconn, $ldapUserData[0]['dn'], $password);
        if (!$ldapbind) {
            CakeLog::error("[LdapAuth] LDAP user authentication failed: " . ldap_error($ldapconn));
            return false;
        }

        if (!isset(self::$conf['ldapEmailField']) && isset($ldapUserData[0]['mail'][0])) {
            // Assign the real user for MISP
            $mispUsername = $ldapUserData[0]['mail'][0];
        } else if (isset(self::$conf['ldapEmailField'])) {
            $mispUsername = $this->getEmailAddress(self::$conf['ldapEmailField'], $ldapUserData);
        } else {
            CakeLog::error("[LdapAuth] User not found in LDAP.");
            throw new UnauthorizedException(__('User could not be authenticated by LDAP.'));
        }

        // Without a username there is nothing to link the MISP account to,
        // and continuing would create a row with an empty email that no
        // later login can find again.
        if (empty($mispUsername)) {
            CakeLog::error(
                "[LdapAuth] No ldapEmailField attribute present on the LDAP entry, cannot identify the user."
            );
            throw new UnauthorizedException(__('User could not be authenticated by LDAP.'));
        }

        // Find user with real username (mail)
        $user = $this->_findUser($mispUsername);

        if ($user && !self::$conf['updateUser']) {
            return $user;
        }

        // Insert user in database if not existent
        $userModel = ClassRegistry::init($this->settings['userModel']);

        // Group memberships can decide the role, the organisation or both, so
        // read them once, under the reader bind, if either mapping needs them.
        $groups = [];
        if ($this->getRoleGroupMapping() || !empty(self::$conf['ldapOrgGroupMapping'])) {
            $ldapbind = ldap_bind($ldapconn, self::$conf['ldapReaderUser'],  self::$conf['ldapReaderPassword']);
            if (!$ldapbind) {
                CakeLog::error("[LdapAuth] Invalid LDAP reader user credentials: " . ldap_error($ldapconn));
                throw new UnauthorizedException(__('User could not be authenticated by LDAP.'));
            }
            $groups = $this->getUserMemberships($ldapconn, $ldapUserData);
        }

        $orgId = $this->getOrganisationId($userModel, $ldapUserData, $groups);

        // If not in config, take first local organisation
        if (!isset($orgId)) {
            $firstOrg = $userModel->Organisation->find(
                'first',
                [
                    'conditions' => [
                        'Organisation.local' => true
                    ],
                    'order' => 'Organisation.id ASC'
                ]
            );
            $orgId = $firstOrg['Organisation']['id'];
        }

        // Set role_id from the role attribute, group membership or default role
        $roleId = $this->getRoleId($userModel, $ldapUserData, $groups);

        // Refuse login when the directory was meant to decide the role and no
        // role came out of it. For existing users we also disable the account;
        // for new users we just refuse so we never hit the INSERT with a NULL
        // role_id.
        if ($roleId === null) {
            if ($user) {
                CakeLog::debug("[LdapAuth] User has no valid role anymore, disabling user.");
                $this->disableUser($mispUsername);
            } else {
                CakeLog::error("[LdapAuth] Could not resolve a role from LDAP, refusing login.");
            }
            throw new UnauthorizedException(__('User could not be authenticated by LDAP.'));
        }

        if (!$user) {
            // Create user
            $userData = ['User' => [
                'email' => $mispUsername,
                'org_id' => $orgId,
                'password' => '',
                'confirm_password' => '',
                'authkey' => $userModel->generateAuthKey(),
                'nids_sid' => 4000000,
                'newsread' => 0,
                'role_id' => $roleId,
                'change_pw' => 0,
            ]];
            $userModel->save($userData, false);
        } else {
            // Update existing user
            $user['email'] = $mispUsername;
            $user['org_id'] = $orgId;
            $user['role_id'] = $roleId;
            # Reenable user in case it has been disabled
            $user['disabled'] = 0;

            $userModel->save($user, false);
        }

        return $this->_findUser(
            $mispUsername
        );
    }
}
