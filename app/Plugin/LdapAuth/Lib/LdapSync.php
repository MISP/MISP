<?php

App::uses('LdapAuthenticate', 'LdapAuth.Controller/Component/Auth');

/**
 * Reconciles MISP accounts with the LDAP directory outside of a login.
 *
 * Provides the same interface as OidcAuth's Lib/Oidc so `cake User
 * check_validity` can drive either: isUserValid() reports, blockInvalidUser()
 * additionally disables.
 *
 * Extends LdapAuthenticate on purpose rather than reimplementing the lookups.
 * A separate copy of "which entry is this, is it disabled, what role and
 * organisation does it get" would drift from the login path, and the two
 * disagreeing about who is allowed in is exactly the bug worth avoiding.
 */
class LdapSync extends LdapAuthenticate
{
    /** @var User */
    private $User;

    public function __construct(User $user)
    {
        parent::__construct();
        $this->User = $user;
        // BaseAuthenticate would normally populate this; nothing here logs
        // anyone in, but _findUser() and friends still expect it.
        $this->settings = ['userModel' => 'User', 'fields' => ['username' => 'email']];
    }

    /**
     * Is this MISP account still backed by the directory?
     *
     * @param array $user MISP user row
     * @param bool $verbose Print what was decided and why
     * @param bool $update Apply organisation and role changes
     * @return bool
     */
    public function isUserValid(array $user, $verbose = false, $update = false)
    {
        if (empty($user['id']) || empty($user['email'])) {
            throw new InvalidArgumentException("Invalid user model provided.");
        }

        $ldapconn = $this->ldapConnect();
        if (!ldap_bind($ldapconn, self::$conf['ldapReaderUser'], self::$conf['ldapReaderPassword'])) {
            // A broken reader would otherwise look like "every user has been
            // removed from the directory", which is a lot of damage for a
            // configuration mistake.
            throw new RuntimeException(
                'LDAP reader bind failed: ' . ldap_error($ldapconn) . '. Refusing to judge any account.'
            );
        }

        $entry = $this->findEntryForMispUser($ldapconn, $user['email']);
        if ($entry === null) {
            // Absent from the directory. With mixedAuth this may simply be a
            // local account that never came from LDAP, so leave it alone;
            // without it, LDAP is the only way in and the account is dead.
            if (self::$conf['mixedAuth']) {
                $this->report($verbose, $user, 'not in LDAP, but mixedAuth is enabled, leaving alone');
                return true;
            }
            $this->report($verbose, $user, 'not found in LDAP');
            return false;
        }

        if ($this->isDirectoryAccountDisabled($entry)) {
            $this->report($verbose, $user, 'disabled in LDAP (userAccountControl)');
            return false;
        }

        $groups = [];
        if ($this->getRoleGroupMapping() || !empty(self::$conf['ldapOrgGroupMapping'])) {
            $groups = $this->getUserMemberships($ldapconn, $entry);
        }

        // A user the directory no longer grants a role to is refused at login,
        // so treat it the same here rather than leaving a live account behind.
        $roleId = $this->getRoleId($this->User, $entry, $groups);
        if ($roleId === null) {
            $this->report($verbose, $user, 'no role resolved from LDAP');
            return false;
        }

        $orgId = $this->getOrganisationId($this->User, $entry, $groups);

        if ($update) {
            $this->applyChanges($user, $orgId, $roleId, $verbose);
        }

        return true;
    }

    /**
     * @param array $user MISP user row
     * @param bool $verbose
     * @param bool $update
     * @return bool Whether the user was valid; invalid users are disabled.
     */
    public function blockInvalidUser(array $user, $verbose = false, $update = false)
    {
        $isValid = $this->isUserValid($user, $verbose, $update);
        if ($isValid || !empty($user['disabled'])) {
            return $isValid;
        }

        if ($this->isSiteAdmin($user)) {
            // Reported, never disabled. There is no way to tell an
            // LDAP-provisioned account from a local one -- the plugin creates
            // users with an empty password, which is then hashed like any
            // other -- so a directory that does not list the built-in admin
            // makes it look invalid. Disabling every site admin locks the
            // instance out of its own administration, and that is not
            // recoverable through MISP. Revoke admins in the directory and
            // disable them by hand.
            $this->report($verbose, $user, 'site admin, NOT disabled; revoke by hand if intended');
            return $isValid;
        }

        $this->User->updateField($user, 'disabled', true);
        $this->report($verbose, $user, 'disabled in MISP');
        return $isValid;
    }

    /**
     * Whether the account carries site admin permissions.
     *
     * The shell fetches users without their Role, so look it up.
     */
    private function isSiteAdmin(array $user)
    {
        if (empty($user['role_id'])) {
            return false;
        }

        $role = $this->User->Role->find('first', [
            'conditions' => ['Role.id' => $user['role_id']],
            'fields' => ['Role.perm_site_admin'],
            'recursive' => -1,
        ]);

        return !empty($role['Role']['perm_site_admin']);
    }

    /**
     * Finds the entry a MISP account came from.
     *
     * Deliberately searches on `ldapEmailField` rather than
     * `ldapSearchAttribute`: the MISP address is by definition the value of
     * one of the former, while the latter is whatever people type to log in
     * and may be something else entirely, such as a uid.
     *
     * @return array|null ldap_get_entries() result, or null when absent
     */
    private function findEntryForMispUser($ldapconn, $email)
    {
        $fields = (array)self::$conf['ldapEmailField'];
        $escaped = ldap_escape($email, '', LDAP_ESCAPE_FILTER);

        // `dn` is not an attribute, so it cannot be searched for. When the
        // accounts are linked by DN the address *is* the DN, so read it.
        if (in_array('dn', array_map('strtolower', $fields), true)) {
            $result = @ldap_read($ldapconn, $email, '(objectClass=*)', self::$conf['ldapEmailField']);
            if ($result) {
                $entries = ldap_get_entries($ldapconn, $result);
                if (!empty($entries['count'])) {
                    return $entries;
                }
            }
        }

        $clauses = '';
        foreach ($fields as $field) {
            if (strtolower($field) === 'dn') {
                continue;
            }
            $clauses .= '(' . $field . '=' . $escaped . ')';
        }
        if ($clauses === '') {
            return null;
        }

        $filter = '(|' . $clauses . ')';
        if (!empty(self::$conf['ldapSearchFilter'])) {
            $filter = '(&' . self::$conf['ldapSearchFilter'] . $filter . ')';
        }

        $result = ldap_search($ldapconn, self::$conf['ldapDn'], $filter);
        if (!$result) {
            throw new RuntimeException('LDAP search failed: ' . ldap_error($ldapconn));
        }

        $entries = ldap_get_entries($ldapconn, $result);
        return empty($entries['count']) ? null : $entries;
    }

    /**
     * Writes organisation and role back, when the directory disagrees.
     *
     * Gated on `LdapAuth.updateUser` as well as the caller's --update: the
     * setting is what says the directory owns these fields, and an instance
     * that has turned it off does not expect a CLI run to overrule it.
     */
    private function applyChanges(array $user, $orgId, $roleId, $verbose)
    {
        if (!self::$conf['updateUser']) {
            $this->report($verbose, $user, 'organisation and role left alone, updateUser is disabled');
            return;
        }

        if ($this->isSiteAdmin($user)) {
            // Same reasoning as blockInvalidUser(): demoting the last site
            // admin removes administrative access just as effectively as
            // disabling it.
            $this->report($verbose, $user, 'site admin, organisation and role left alone');
            return;
        }

        $changes = [];
        if ((int)$user['org_id'] !== (int)$orgId) {
            $changes['org_id'] = $orgId;
        }
        if ((int)$user['role_id'] !== (int)$roleId) {
            $changes['role_id'] = $roleId;
        }
        if (empty($changes)) {
            return;
        }

        foreach ($changes as $field => $value) {
            $this->User->updateField($user, $field, $value);
            $this->report($verbose, $user, sprintf('%s %s -> %s', $field, $user[$field], $value));
        }
    }

    private function report($verbose, array $user, $message)
    {
        CakeLog::info("[LdapAuth] {$user['email']}: $message");
        if ($verbose) {
            echo "  {$user['email']}: $message\n";
        }
    }
}
