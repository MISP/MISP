<?php
/**
 * CLIOrganisationsTrait
 *
 * Provides organisation-specific entity configuration,
 * field metadata, and CRUD operations for CLIShell.
 * Add/edit/delete operations require site admin access.
 */
trait CLIOrganisationsTrait
{
    /**
     * Get entity configuration for organisations.
     *
     * @return array Entity config keyed by name.
     */
    private function __getOrganisationEntityConfig()
    {
        return [
            'organisation' => [
                'model' => 'Organisation',
                'aliases' => [
                    'organisations', 'org', 'orgs',
                ],
                'listFields' => [
                    'id', 'name', 'uuid',
                    'nationality', 'sector',
                ],
                'editableFields' => [
                    'name', 'type', 'nationality',
                    'sector', 'description',
                    'contacts', 'local',
                ],
                'writeAdminOnly' => true,
                'filters' => [
                    'searchall', 'nationality',
                    'sector', 'local',
                ],
            ],
        ];
    }

    /**
     * Get field metadata for organisation prompts.
     *
     * @return array Field metadata keyed by entity.
     */
    private function __getOrganisationFieldMeta()
    {
        return [
            'organisation' => [
                'name' => [
                    'type' => 'string',
                    'required' => true,
                    'help' => 'Organisation name',
                ],
                'type' => [
                    'type' => 'string',
                    'required' => false,
                    'help' => 'Organisation type',
                ],
                'nationality' => [
                    'type' => 'string',
                    'required' => false,
                    'help' => 'Country/nationality',
                ],
                'sector' => [
                    'type' => 'string',
                    'required' => false,
                    'help' => 'Industry sector',
                ],
                'description' => [
                    'type' => 'string',
                    'required' => false,
                    'help' => 'Description',
                ],
                'contacts' => [
                    'type' => 'string',
                    'required' => false,
                    'help' => 'Contact information',
                ],
                'local' => [
                    'type' => 'boolean',
                    'required' => false,
                    'default' => '1',
                    'help' => 'Local org (0/1)',
                ],
            ],
        ];
    }

    /**
     * Fetch a paginated list of organisations.
     *
     * @param array $filters Search filters.
     * @return array Formatted organisation rows.
     */
    private function __fetchOrganisationList(
        $filters
    ) {
        $conditions = [];
        $limit = isset($filters['limit'])
            ? (int)$filters['limit']
            : $this->__perPage;
        $page = isset($filters['page'])
            ? (int)$filters['page'] : 1;

        if (isset($filters['searchall'])) {
            $conditions['Organisation.name LIKE'] =
                '%' . $filters['searchall'] . '%';
        }
        if (isset($filters['nationality'])) {
            $conditions[
                'Organisation.nationality'
            ] = $filters['nationality'];
        }
        if (isset($filters['sector'])) {
            $conditions['Organisation.sector'] =
                $filters['sector'];
        }
        if (isset($filters['local'])) {
            $conditions['Organisation.local'] =
                $filters['local'];
        }

        // Honour hide_organisation_index_from_users
        // exactly as OrganisationsController::index.
        $aclConditions = $this->Organisation
            ->createConditions($this->__user);
        if (!empty($aclConditions)) {
            $conditions[] = $aclConditions;
        }

        $orgs = $this->Organisation->find('all', [
            'conditions' => $conditions,
            'fields' => [
                'Organisation.id',
                'Organisation.name',
                'Organisation.uuid',
                'Organisation.nationality',
                'Organisation.sector',
            ],
            'recursive' => -1,
            'limit' => $limit,
            'page' => $page,
            'order' => [
                'Organisation.name' => isset(
                    $filters['sort_order']
                )
                ? $filters['sort_order'] : 'ASC',
            ],
        ]);

        $results = [];
        foreach ($orgs as $org) {
            $o = $org['Organisation'];
            $results[] = [
                'id' => $o['id'],
                'name' => $o['name'],
                'uuid' => $o['uuid'],
                'nationality' =>
                    isset($o['nationality'])
                    ? $o['nationality'] : '',
                'sector' => isset($o['sector'])
                    ? $o['sector'] : '',
            ];
        }

        return $results;
    }

    /**
     * Fetch full detail for a single organisation.
     *
     * Mirrors OrganisationsController::view():
     * canSee() enforces
     * hide_organisation_index_from_users, the
     * field list is the web's, and created_by is
     * only read for site admins and for the org's
     * own org admins.
     *
     * @param int $id Organisation ID.
     * @return array|null Organisation data or null.
     */
    private function __fetchOrganisationDetail(
        $id
    ) {
        if (
            !$this->Organisation->canSee(
                $this->__user, $id
            )
        ) {
            return null;
        }
        $role = $this->__user['Role'];
        $fullAccess = !empty($role['perm_site_admin'])
            || (
                !empty($role['perm_admin'])
                && (int)$this->__user['org_id']
                    === (int)$id
            );
        $fields = [
            'id', 'name', 'date_created',
            'date_modified', 'type', 'nationality',
            'sector', 'contacts', 'description',
            'local', 'uuid', 'restricted_to_domain',
        ];
        if ($fullAccess) {
            $fields[] = 'created_by';
        }
        $org = $this->Organisation->find('first', [
            'conditions' => [
                'Organisation.id' => $id,
            ],
            'fields' => $fields,
            'recursive' => -1,
        ]);
        return !empty($org) ? $org : null;
    }

    /**
     * Add a new organisation interactively.
     *
     * @return void
     */
    private function __addOrganisation()
    {
        $values = $this->__promptForFields(
            'organisation'
        );
        if ($values === false) {
            return;
        }
        if (
            !$this->__promptConfirm(
                'Create organisation?'
            )
        ) {
            $this->out('Cancelled.');
            return;
        }

        $data = ['Organisation' => $values];
        $data['Organisation']['created_by'] =
            $this->__user['id'];

        $this->Organisation->create();
        $result = $this->Organisation->save($data);
        if ($result) {
            $this->out(
                'Organisation #'
                . $this->Organisation->id
                . ' created successfully.'
            );
        } else {
            $this->err(
                'Failed to create organisation.'
            );
            if (
                !empty(
                    $this->Organisation
                        ->validationErrors
                )
            ) {
                foreach (
                    $this->Organisation
                        ->validationErrors
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
     * Edit an existing organisation.
     *
     * @param int $id Organisation ID.
     * @return void
     */
    private function __editOrganisation($id, $fields = null)
    {
        $existing =
            $this->__fetchOrganisationDetail($id);
        if (empty($existing)) {
            $this->err(
                'Organisation #' . $id
                . ' not found.'
            );
            return false;
        }
        $editableFields =
            $this->__entityConfig['organisation']
                ['editableFields'];
        if ($fields !== null) {
            $editableFields = array_values(
                array_intersect(
                    $editableFields, $fields
                )
            );
        }
        $values = $this->__promptForFields(
            'organisation',
            $existing['Organisation'],
            $editableFields
        );
        if ($values === false) {
            return false;
        }
        if (
            !$this->__promptConfirm(
                'Save changes to organisation #'
                . $id . '?'
            )
        ) {
            $this->out('Cancelled.');
            return false;
        }
        $data = [
            'Organisation' => array_merge(
                ['id' => $id],
                $values
            ),
        ];
        $this->Organisation->id = $id;
        $result = $this->Organisation->save(
            $data, true, $editableFields
        );
        if ($result) {
            $this->out(
                'Organisation #' . $id
                . ' updated successfully.'
            );
            return true;
        } else {
            $this->err(
                'Failed to update organisation #'
                . $id . '.'
            );
            if (
                !empty(
                    $this->Organisation
                        ->validationErrors
                )
            ) {
                foreach (
                    $this->Organisation
                        ->validationErrors
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
        return false;
    }

    /**
     * Delete an organisation with confirmation.
     *
     * @param int $id Organisation ID.
     * @return void
     */
    private function __deleteOrganisation($id)
    {
        $org = $this->Organisation->find('first', [
            'conditions' => [
                'Organisation.id' => $id,
            ],
            'fields' => [
                'Organisation.id',
                'Organisation.name',
            ],
            'recursive' => -1,
        ]);
        if (empty($org)) {
            $this->err(
                'Organisation #' . $id
                . ' not found.'
            );
            return;
        }

        $userCount = $this->User->find('count', [
            'conditions' => [
                'User.org_id' => $id,
            ],
            'recursive' => -1,
        ]);
        if ($userCount > 0) {
            $this->err(
                'Cannot delete: organisation has '
                . $userCount . ' user(s).'
            );
            return;
        }

        $eventCount = $this->Event->find('count', [
            'conditions' => [
                'OR' => [
                    'Event.org_id' => $id,
                    'Event.orgc_id' => $id,
                ],
            ],
            'recursive' => -1,
        ]);
        if ($eventCount > 0) {
            $this->err(
                'Cannot delete: organisation is '
                . 'referenced by ' . $eventCount
                . ' event(s).'
            );
            return;
        }

        $name = $org['Organisation']['name'];
        if (
            !$this->__promptConfirm(
                'Delete organisation #' . $id
                . " '" . $name . "'?"
                . ' This cannot be undone.'
            )
        ) {
            $this->out('Cancelled.');
            return;
        }
        $result = $this->Organisation->delete($id);
        if ($result) {
            $this->out(
                'Organisation #' . $id
                . ' deleted successfully.'
            );
        } else {
            $this->err(
                'Failed to delete organisation #'
                . $id . '.'
            );
        }
    }
}
