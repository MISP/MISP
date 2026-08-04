<?php
/**
 * CLIUsersTrait
 *
 * Provides user-specific entity configuration,
 * field metadata, and CRUD operations for CLIShell.
 * All operations require site admin access.
 */
trait CLIUsersTrait
{
    /**
     * Get entity configuration for users.
     *
     * @return array Entity config keyed by name.
     */
    private function __getUserEntityConfig()
    {
        return [
            'user' => [
                'model' => 'User',
                'aliases' => ['users'],
                'listFields' => [
                    'id', 'email', 'org_id',
                    'role_id', 'disabled',
                ],
                'editableFields' => [
                    'email', 'org_id', 'role_id',
                    'disabled', 'change_pw',
                    'autoalert', 'contactalert',
                ],
                'adminOnly' => true,
            ],
        ];
    }

    /**
     * Get field metadata for user prompts.
     *
     * @return array Field metadata keyed by entity.
     */
    private function __getUserFieldMeta()
    {
        return [
            'user' => [
                'email' => [
                    'type' => 'string',
                    'required' => true,
                    'help' => 'User email address',
                ],
                'org_id' => [
                    'type' => 'integer',
                    'required' => true,
                    'help' => 'Organisation ID',
                ],
                'role_id' => [
                    'type' => 'integer',
                    'required' => true,
                    'help' => 'Role ID',
                ],
                'password' => [
                    'type' => 'string',
                    'required' => false,
                    'help' => 'Password (auto-'
                        . 'generated if empty)',
                ],
                'disabled' => [
                    'type' => 'boolean',
                    'required' => false,
                    'default' => '0',
                    'help' => 'Disabled (0/1)',
                ],
                'change_pw' => [
                    'type' => 'boolean',
                    'required' => false,
                    'default' => '1',
                    'help' => 'Force password '
                        . 'change (0/1)',
                ],
                'autoalert' => [
                    'type' => 'boolean',
                    'required' => false,
                    'default' => '0',
                    'help' => 'Publish alerts (0/1)',
                ],
                'contactalert' => [
                    'type' => 'boolean',
                    'required' => false,
                    'default' => '0',
                    'help' => 'Contact alerts (0/1)',
                ],
            ],
        ];
    }

    /**
     * Fetch a paginated list of users.
     *
     * @param array $filters Search filters.
     * @return array Formatted user rows.
     */
    private function __fetchUserList($filters)
    {
        $conditions = [];
        $limit = isset($filters['limit'])
            ? (int)$filters['limit']
            : $this->__perPage;
        $page = isset($filters['page'])
            ? (int)$filters['page'] : 1;

        if (isset($filters['org_id'])) {
            $conditions['User.org_id'] =
                $filters['org_id'];
        }
        if (isset($filters['role_id'])) {
            $conditions['User.role_id'] =
                $filters['role_id'];
        }
        if (isset($filters['disabled'])) {
            $conditions['User.disabled'] =
                $filters['disabled'];
        }
        if (isset($filters['searchall'])) {
            $conditions['User.email LIKE'] =
                '%' . $filters['searchall'] . '%';
        }

        $users = $this->User->find('all', [
            'conditions' => $conditions,
            'fields' => [
                'User.id', 'User.email',
                'User.org_id', 'User.role_id',
                'User.disabled',
            ],
            'recursive' => -1,
            'limit' => $limit,
            'page' => $page,
            'order' => [
                'User.id' => isset(
                    $filters['sort_order']
                )
                ? $filters['sort_order'] : 'DESC',
            ],
        ]);

        $orgIds = [];
        $roleIds = [];
        foreach ($users as $user) {
            $orgIds[] = $user['User']['org_id'];
            $roleIds[] = $user['User']['role_id'];
        }
        $this->__prefetchFK('org', $orgIds);
        $this->__prefetchFK('role', $roleIds);

        $results = [];
        foreach ($users as $user) {
            $u = $user['User'];
            $results[] = [
                'id' => $u['id'],
                'email' => $u['email'],
                'org_id' => $this->__resolveFK(
                    'org', $u['org_id']
                ),
                'role_id' => $this->__resolveFK(
                    'role', $u['role_id']
                ),
                'disabled' => !empty(
                    $u['disabled']
                ) ? 'Yes' : 'No',
            ];
        }

        return $results;
    }

    /**
     * Fetch full detail for a single user.
     *
     * @param int $id User ID.
     * @return array|null User data or null.
     */
    private function __fetchUserDetail($id)
    {
        $user = $this->User->find('first', [
            'conditions' => ['User.id' => $id],
            'contain' => [
                'Role' => [
                    'fields' => ['Role.name'],
                ],
                'Organisation' => [
                    'fields' => [
                        'Organisation.name',
                    ],
                ],
            ],
        ]);
        if (!empty($user)) {
            unset($user['User']['password']);
            unset($user['User']['authkey']);
            unset($user['User']['totp']);
        }
        return !empty($user) ? $user : null;
    }

    /**
     * Add a new user interactively.
     *
     * @return void
     */
    private function __addUser()
    {
        $values = $this->__promptForFields(
            'user'
        );
        if ($values === false) {
            return;
        }

        $org = $this->Organisation->find(
            'first',
            [
                'conditions' => [
                    'Organisation.id' =>
                        $values['org_id'],
                ],
                'fields' => ['Organisation.name'],
                'recursive' => -1,
            ]
        );
        if (empty($org)) {
            $this->err(
                'Organisation #'
                . $values['org_id']
                . ' not found.'
            );
            return;
        }

        $role = $this->Role->find('first', [
            'conditions' => [
                'Role.id' => $values['role_id'],
            ],
            'fields' => ['Role.name'],
            'recursive' => -1,
        ]);
        if (empty($role)) {
            $this->err(
                'Role #' . $values['role_id']
                . ' not found.'
            );
            return;
        }

        $this->out('');
        $this->out(
            '  Organisation: '
            . $org['Organisation']['name']
        );
        $this->out(
            '  Role: ' . $role['Role']['name']
        );

        if (
            !$this->__promptConfirm('Create user?')
        ) {
            $this->out('Cancelled.');
            return;
        }

        $userData = $values;
        if (!empty($userData['password'])) {
            $userData['confirm_password'] =
                $userData['password'];
            $userData['enable_password'] = true;
        }
        $userData['invited_by'] =
            $this->__user['id'];

        $this->User->create();
        $result = $this->User->save($userData);
        if ($result) {
            $newId = $this->User->id;
            $newUser = $this->User->find('first', [
                'conditions' => [
                    'User.id' => $newId,
                ],
                'fields' => [
                    'User.id', 'User.authkey',
                ],
                'recursive' => -1,
            ]);
            $this->out(
                'User #' . $newId
                . ' created successfully.'
            );
            if (
                !empty(
                    $newUser['User']['authkey']
                )
            ) {
                $this->out(
                    '  Auth key: '
                    . $newUser['User']['authkey']
                );
            }
            if (
                empty($values['password'])
            ) {
                $this->out(
                    '  Password was auto-generated.'
                    . ' User must change on login.'
                );
            }
        } else {
            $this->err(
                'Failed to create user.'
            );
            if (
                !empty(
                    $this->User->validationErrors
                )
            ) {
                foreach (
                    $this->User->validationErrors
                    as $field => $errs
                ) {
                    $errMsg = is_array($errs)
                        ? implode(', ', $errs)
                        : $errs;
                    $this->err(
                        '  ' . $field
                        . ': ' . $errMsg
                    );
                }
            }
        }
    }

    /**
     * Edit an existing user interactively.
     *
     * @param int $id User ID.
     * @return void
     */
    private function __editUser($id)
    {
        $existing = $this->__fetchUserDetail($id);
        if (empty($existing)) {
            $this->err(
                'User #' . $id . ' not found.'
            );
            return;
        }
        $editableFields =
            $this->__entityConfig['user']
                ['editableFields'];
        $values = $this->__promptForFields(
            'user',
            $existing['User'],
            $editableFields
        );
        if ($values === false) {
            return;
        }

        $this->out('');
        $this->out(
            '  Editing: '
            . $existing['User']['email']
        );
        if (
            !$this->__promptConfirm(
                'Save changes to user #'
                . $id . '?'
            )
        ) {
            $this->out('Cancelled.');
            return;
        }

        $data = array_merge(
            ['id' => $id],
            $values
        );
        $this->User->id = $id;
        $result = $this->User->save(
            ['User' => $data],
            true,
            $editableFields
        );
        if ($result) {
            $this->out(
                'User #' . $id
                . ' updated successfully.'
            );
        } else {
            $this->err(
                'Failed to update user #'
                . $id . '.'
            );
            if (
                !empty(
                    $this->User->validationErrors
                )
            ) {
                foreach (
                    $this->User->validationErrors
                    as $field => $errs
                ) {
                    $errMsg = is_array($errs)
                        ? implode(', ', $errs)
                        : $errs;
                    $this->err(
                        '  ' . $field
                        . ': ' . $errMsg
                    );
                }
            }
        }
    }

    /**
     * Delete (disable) a user with confirmation.
     *
     * Prompts the user to choose between disabling
     * (recommended) and hard-deleting the user.
     *
     * @param int $id User ID.
     * @return void
     */
    private function __deleteUser($id)
    {
        $user = $this->User->find('first', [
            'conditions' => ['User.id' => $id],
            'fields' => [
                'User.id', 'User.email',
                'User.disabled',
            ],
            'recursive' => -1,
        ]);
        if (empty($user)) {
            $this->err(
                'User #' . $id . ' not found.'
            );
            return;
        }
        if ((int)$id === (int)$this->__user['id']) {
            $this->err(
                'Cannot delete your own account.'
            );
            return;
        }

        $email = $user['User']['email'];
        $this->out('');
        $this->out(
            'User: ' . $email
        );
        $this->out(
            'Recommended: disable instead of '
            . 'delete to preserve audit trails.'
        );
        $this->out(
            '  [d] Disable user'
        );
        $this->out(
            '  [D] Hard-delete user (irreversible)'
        );
        $this->out(
            '  [c] Cancel'
        );
        $this->out('  Choice: ', 0);
        $line = fgets($this->__stdin);
        if ($line === false) {
            return;
        }
        $choice = trim($line);

        if ($choice === 'd') {
            if (
                !empty($user['User']['disabled'])
            ) {
                $this->out(
                    'User is already disabled.'
                );
                return;
            }
            $this->User->id = $id;
            $result = $this->User->save(
                [
                    'User' => [
                        'id' => $id,
                        'disabled' => 1,
                    ],
                ],
                true,
                ['disabled']
            );
            if ($result) {
                $this->out(
                    'User #' . $id . ' disabled.'
                );
            } else {
                $this->err(
                    'Failed to disable user #'
                    . $id . '.'
                );
            }
        } elseif ($choice === 'D') {
            if (
                !$this->__promptConfirm(
                    'Permanently delete user #'
                    . $id . ' (' . $email
                    . ')? This cannot be undone.'
                )
            ) {
                $this->out('Cancelled.');
                return;
            }
            $result = $this->User->delete($id);
            if ($result) {
                $this->out(
                    'User #' . $id
                    . ' deleted permanently.'
                );
            } else {
                $this->err(
                    'Failed to delete user #'
                    . $id . '.'
                );
            }
        } else {
            $this->out('Cancelled.');
        }
    }
}
