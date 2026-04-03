<?php
/**
 * CLIRolesTrait
 *
 * Provides role-specific entity configuration,
 * field metadata, and CRUD operations for CLIShell.
 * All operations require site admin access.
 */
trait CLIRolesTrait
{
    /**
     * Get entity configuration for roles.
     *
     * @return array Entity config keyed by name.
     */
    private function __getRoleEntityConfig()
    {
        return [
            'role' => [
                'model' => 'Role',
                'aliases' => ['roles'],
                'listFields' => [
                    'id', 'name', 'permission',
                    'perm_site_admin', 'perm_admin',
                ],
                'editableFields' => [
                    'name', 'permission',
                    'perm_site_admin', 'perm_admin',
                    'perm_sync', 'perm_audit',
                    'perm_auth', 'perm_tagger',
                    'perm_tag_editor',
                    'perm_sharing_group',
                    'perm_sighting', 'perm_delegate',
                    'perm_template',
                    'perm_galaxy_editor',
                    'perm_warninglist',
                    'perm_publish_zmq',
                    'perm_publish_kafka',
                    'perm_analyst_data',
                    'enforce_rate_limit',
                    'rate_limit_count',
                    'max_execution_time',
                    'memory_limit',
                ],
                'adminOnly' => true,
            ],
        ];
    }

    /**
     * Get field metadata for role prompts.
     *
     * @return array Field metadata keyed by entity.
     */
    private function __getRoleFieldMeta()
    {
        return [
            'role' => [
                'name' => [
                    'type' => 'string',
                    'required' => true,
                    'help' => 'Role name',
                ],
                'permission' => [
                    'type' => 'select',
                    'required' => false,
                    'options' => [
                        '0' => 'Read Only',
                        '1' => 'Manage Own Events',
                        '2' => 'Manage Org Events',
                        '3' => 'Manage and Publish',
                    ],
                    'default' => '0',
                    'help' => 'Base permission level',
                ],
                'perm_site_admin' => [
                    'type' => 'boolean',
                    'required' => false,
                    'default' => '0',
                    'help' => 'Site admin (0/1)',
                ],
                'perm_admin' => [
                    'type' => 'boolean',
                    'required' => false,
                    'default' => '0',
                    'help' => 'Org admin (0/1)',
                ],
                'perm_sync' => [
                    'type' => 'boolean',
                    'required' => false,
                    'default' => '0',
                    'help' => 'Sync permission (0/1)',
                ],
                'perm_audit' => [
                    'type' => 'boolean',
                    'required' => false,
                    'default' => '0',
                    'help' => 'Audit access (0/1)',
                ],
                'perm_auth' => [
                    'type' => 'boolean',
                    'required' => false,
                    'default' => '1',
                    'help' => 'Auth key access (0/1)',
                ],
                'perm_tagger' => [
                    'type' => 'boolean',
                    'required' => false,
                    'default' => '0',
                    'help' => 'Can attach/detach '
                        . 'tags (0/1)',
                ],
                'perm_tag_editor' => [
                    'type' => 'boolean',
                    'required' => false,
                    'default' => '0',
                    'help' => 'Can create tags (0/1)',
                ],
                'perm_sharing_group' => [
                    'type' => 'boolean',
                    'required' => false,
                    'default' => '0',
                    'help' => 'Sharing group '
                        . 'editor (0/1)',
                ],
                'perm_sighting' => [
                    'type' => 'boolean',
                    'required' => false,
                    'default' => '0',
                    'help' => 'Can add '
                        . 'sightings (0/1)',
                ],
                'perm_delegate' => [
                    'type' => 'boolean',
                    'required' => false,
                    'default' => '0',
                    'help' => 'Delegation '
                        . 'access (0/1)',
                ],
                'perm_template' => [
                    'type' => 'boolean',
                    'required' => false,
                    'default' => '0',
                    'help' => 'Template '
                        . 'editor (0/1)',
                ],
                'perm_galaxy_editor' => [
                    'type' => 'boolean',
                    'required' => false,
                    'default' => '0',
                    'help' => 'Galaxy editor (0/1)',
                ],
                'perm_warninglist' => [
                    'type' => 'boolean',
                    'required' => false,
                    'default' => '0',
                    'help' => 'Warninglist '
                        . 'editor (0/1)',
                ],
                'perm_publish_zmq' => [
                    'type' => 'boolean',
                    'required' => false,
                    'default' => '0',
                    'help' => 'ZMQ publisher (0/1)',
                ],
                'perm_publish_kafka' => [
                    'type' => 'boolean',
                    'required' => false,
                    'default' => '0',
                    'help' => 'Kafka '
                        . 'publisher (0/1)',
                ],
                'perm_analyst_data' => [
                    'type' => 'boolean',
                    'required' => false,
                    'default' => '0',
                    'help' => 'Analyst data '
                        . 'creator (0/1)',
                ],
                'enforce_rate_limit' => [
                    'type' => 'boolean',
                    'required' => false,
                    'default' => '0',
                    'help' => 'Enforce rate '
                        . 'limit (0/1)',
                ],
                'rate_limit_count' => [
                    'type' => 'integer',
                    'required' => false,
                    'help' => 'Rate limit count',
                ],
                'max_execution_time' => [
                    'type' => 'string',
                    'required' => false,
                    'help' => 'Max execution time '
                        . '(seconds)',
                ],
                'memory_limit' => [
                    'type' => 'string',
                    'required' => false,
                    'help' => 'Memory limit '
                        . '(e.g. 256M, 1G, -1)',
                ],
            ],
        ];
    }

    /**
     * Fetch a paginated list of roles.
     *
     * @param array $filters Search filters.
     * @return array Formatted role rows.
     */
    private function __fetchRoleList($filters)
    {
        $conditions = [];
        $limit = isset($filters['limit'])
            ? (int)$filters['limit']
            : $this->__perPage;
        $page = isset($filters['page'])
            ? (int)$filters['page'] : 1;

        if (isset($filters['searchall'])) {
            $conditions['Role.name LIKE'] =
                '%' . $filters['searchall'] . '%';
        }

        $roles = $this->Role->find('all', [
            'conditions' => $conditions,
            'recursive' => -1,
            'limit' => $limit,
            'page' => $page,
            'order' => [
                'Role.id' => isset(
                    $filters['sort_order']
                )
                ? $filters['sort_order'] : 'ASC',
            ],
        ]);

        $permNames = [
            '0' => 'Read Only',
            '1' => 'Manage Own',
            '2' => 'Manage Org',
            '3' => 'Publish',
        ];

        $results = [];
        foreach ($roles as $role) {
            $r = $role['Role'];
            $permLevel = isset($r['permission'])
                ? (string)$r['permission'] : '0';
            $results[] = [
                'id' => $r['id'],
                'name' => $r['name'],
                'permission' =>
                    isset($permNames[$permLevel])
                    ? $permNames[$permLevel]
                    : $permLevel,
                'perm_site_admin' => !empty(
                    $r['perm_site_admin']
                ) ? 'Yes' : 'No',
                'perm_admin' => !empty(
                    $r['perm_admin']
                ) ? 'Yes' : 'No',
            ];
        }

        return $results;
    }

    /**
     * Fetch full detail for a single role.
     *
     * @param int $id Role ID.
     * @return array|null Role data or null.
     */
    private function __fetchRoleDetail($id)
    {
        return $this->Role->find('first', [
            'conditions' => ['Role.id' => $id],
            'recursive' => -1,
        ]);
    }

    /**
     * Add a new role interactively.
     *
     * @return void
     */
    private function __addRole()
    {
        $values = $this->__promptForFields(
            'role'
        );
        if ($values === false) {
            return;
        }
        if (
            !$this->__promptConfirm('Create role?')
        ) {
            $this->out('Cancelled.');
            return;
        }

        $this->Role->create();
        $result = $this->Role->save(
            ['Role' => $values]
        );
        if ($result) {
            $this->out(
                'Role #' . $this->Role->id
                . ' created successfully.'
            );
        } else {
            $this->err('Failed to create role.');
            if (
                !empty(
                    $this->Role->validationErrors
                )
            ) {
                foreach (
                    $this->Role->validationErrors
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
     * Edit an existing role interactively.
     *
     * @param int $id Role ID.
     * @return void
     */
    private function __editRole($id)
    {
        $existing = $this->__fetchRoleDetail($id);
        if (empty($existing)) {
            $this->err(
                'Role #' . $id . ' not found.'
            );
            return;
        }
        $editableFields =
            $this->__entityConfig['role']
                ['editableFields'];
        $values = $this->__promptForFields(
            'role',
            $existing['Role'],
            $editableFields
        );
        if ($values === false) {
            return;
        }
        if (
            !$this->__promptConfirm(
                'Save changes to role #'
                . $id . '?'
            )
        ) {
            $this->out('Cancelled.');
            return;
        }
        $data = [
            'Role' => array_merge(
                ['id' => $id],
                $values
            ),
        ];
        $this->Role->id = $id;
        $result = $this->Role->save($data);
        if ($result) {
            $this->out(
                'Role #' . $id
                . ' updated successfully.'
            );
        } else {
            $this->err(
                'Failed to update role #'
                . $id . '.'
            );
            if (
                !empty(
                    $this->Role->validationErrors
                )
            ) {
                foreach (
                    $this->Role->validationErrors
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
     * Delete a role with confirmation.
     *
     * @param int $id Role ID.
     * @return void
     */
    private function __deleteRole($id)
    {
        $role = $this->Role->find('first', [
            'conditions' => ['Role.id' => $id],
            'fields' => [
                'Role.id', 'Role.name',
            ],
            'recursive' => -1,
        ]);
        if (empty($role)) {
            $this->err(
                'Role #' . $id . ' not found.'
            );
            return;
        }

        $userCount = $this->User->find('count', [
            'conditions' => [
                'User.role_id' => $id,
            ],
            'recursive' => -1,
        ]);
        if ($userCount > 0) {
            $this->err(
                'Cannot delete: role is assigned '
                . 'to ' . $userCount . ' user(s).'
            );
            return;
        }

        $name = $role['Role']['name'];
        if (
            !$this->__promptConfirm(
                'Delete role #' . $id
                . " '" . $name . "'?"
                . ' This cannot be undone.'
            )
        ) {
            $this->out('Cancelled.');
            return;
        }
        $result = $this->Role->delete($id);
        if ($result) {
            $this->out(
                'Role #' . $id
                . ' deleted successfully.'
            );
        } else {
            $this->err(
                'Failed to delete role #'
                . $id . '.'
            );
        }
    }
}
