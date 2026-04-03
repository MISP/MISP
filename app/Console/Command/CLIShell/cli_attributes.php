<?php
/**
 * CLIAttributesTrait
 *
 * Provides attribute-specific entity configuration,
 * field metadata, and CRUD operations for CLIShell.
 */
trait CLIAttributesTrait
{
    /**
     * Get entity configuration for attributes.
     *
     * @return array Entity config keyed by name.
     */
    private function __getAttributeEntityConfig()
    {
        return [
            'attribute' => [
                'model' => 'MispAttribute',
                'alias' => 'Attribute',
                'aliases' => ['attributes'],
                'listFields' => [
                    'id', 'event_id', 'type',
                    'category', 'value', 'to_ids',
                    'comment',
                ],
                'editableFields' => [
                    'category', 'type', 'value',
                    'to_ids', 'comment', 'distribution',
                    'sharing_group_id',
                    'disable_correlation',
                    'first_seen', 'last_seen',
                ],
            ],
        ];
    }

    /**
     * Get field metadata for attribute prompts.
     *
     * @return array Field metadata keyed by entity.
     */
    private function __getAttributeFieldMeta()
    {
        return [
            'attribute' => [
                'type' => [
                    'type' => 'autocomplete',
                    'required' => true,
                    'source' => 'attributeTypes',
                    'help' => 'Attribute type '
                        . '(e.g. ip-dst, domain, md5)',
                ],
                'category' => [
                    'type' => 'autocomplete',
                    'required' => false,
                    'source' => 'attributeCategories',
                    'help' => 'Attribute category',
                ],
                'value' => [
                    'type' => 'string',
                    'required' => true,
                    'help' => 'Attribute value',
                ],
                'to_ids' => [
                    'type' => 'boolean',
                    'required' => false,
                    'default' => '1',
                    'help' => 'IDS flag (0/1)',
                ],
                'comment' => [
                    'type' => 'string',
                    'required' => false,
                    'help' => 'Comment',
                ],
                'distribution' => [
                    'type' => 'select',
                    'required' => false,
                    'options' => [
                        '0' => 'Your organisation only',
                        '1' => 'This community only',
                        '2' => 'Connected communities',
                        '3' => 'All communities',
                        '4' => 'Sharing group',
                        '5' => 'Inherit event',
                    ],
                    'default' => '5',
                    'help' => 'Distribution level',
                ],
                'sharing_group_id' => [
                    'type' => 'integer',
                    'required' => false,
                    'help' => 'Sharing group ID '
                        . '(when distribution=4)',
                ],
                'disable_correlation' => [
                    'type' => 'boolean',
                    'required' => false,
                    'default' => '0',
                    'help' => 'Disable correlation (0/1)',
                ],
                'first_seen' => [
                    'type' => 'string',
                    'required' => false,
                    'help' => 'First seen datetime',
                ],
                'last_seen' => [
                    'type' => 'string',
                    'required' => false,
                    'help' => 'Last seen datetime',
                ],
            ],
        ];
    }

    /**
     * Fetch a paginated list of attributes.
     *
     * @param array $filters Search filters.
     * @return array Formatted attribute rows.
     */
    private function __fetchAttributeList($filters)
    {
        $conditions = [
            'Attribute.deleted' => 0,
        ];
        $limit = isset($filters['limit'])
            ? (int)$filters['limit']
            : $this->__perPage;
        $page = isset($filters['page'])
            ? (int)$filters['page'] : 1;

        if (
            $this->__context['entity'] === 'event'
            && !empty($this->__context['id'])
        ) {
            $conditions['Attribute.event_id'] =
                $this->__context['id'];
        }
        if (
            $this->__context['entity'] === 'object'
            && !empty($this->__context['id'])
        ) {
            $conditions['Attribute.object_id'] =
                $this->__context['id'];
        }
        if (isset($filters['eventid'])) {
            $conditions['Attribute.event_id'] =
                $filters['eventid'];
        }
        if (isset($filters['type'])) {
            $conditions['Attribute.type'] =
                $filters['type'];
        }
        if (isset($filters['category'])) {
            $conditions['Attribute.category'] =
                $filters['category'];
        }
        if (isset($filters['to_ids'])) {
            $conditions['Attribute.to_ids'] =
                $filters['to_ids'];
        }
        if (isset($filters['searchall'])) {
            $conditions['Attribute.value LIKE'] =
                '%' . $filters['searchall'] . '%';
        }

        if (
            empty(
                $this->__user['Role']
                    ['perm_site_admin']
            )
        ) {
            $conditions[] =
                $this->__attributeAclConditions();
        }

        $isSiteAdmin = !empty(
            $this->__user['Role']
                ['perm_site_admin']
        );
        $findParams = [
            'conditions' => $conditions,
            'fields' => [
                'Attribute.id',
                'Attribute.event_id',
                'Attribute.type',
                'Attribute.category',
                'Attribute.value',
                'Attribute.to_ids',
                'Attribute.comment',
            ],
            'recursive' => -1,
            'limit' => $limit,
            'page' => $page,
            'order' => [
                'Attribute.id' => isset(
                    $filters['sort_order']
                )
                ? $filters['sort_order']
                : 'DESC',
            ],
        ];

        if (!$isSiteAdmin) {
            $findParams['joins'] = [
                [
                    'table' => 'events',
                    'alias' => 'Event',
                    'type' => 'INNER',
                    'conditions' => [
                        'Event.id = '
                        . 'Attribute.event_id',
                    ],
                ],
            ];
        }

        $attributes =
            $this->MispAttribute->find(
                'all', $findParams
            );

        $results = [];
        $eventIds = array_column(
            array_column($attributes, 'Attribute'),
            'event_id'
        );
        $this->__prefetchFK('event', $eventIds);

        foreach ($attributes as $attr) {
            $a = $attr['Attribute'];
            $results[] = [
                'id' => $a['id'],
                'event_id' => $this->__resolveFK(
                    'event', $a['event_id']
                ),
                'type' => $a['type'],
                'category' => $a['category'],
                'value' => $a['value'],
                'to_ids' => !empty($a['to_ids'])
                    ? 'Yes' : 'No',
                'comment' => isset($a['comment'])
                    ? $a['comment'] : '',
            ];
        }

        return $results;
    }

    /**
     * Build ACL conditions for attribute queries.
     *
     * Non-admin users may not see attributes with
     * distribution 0 on events they don't own, or
     * distribution 4 with unauthorised sharing groups.
     *
     * @return array CakePHP conditions array
     */
    private function __attributeAclConditions()
    {
        $userOrgId = $this->__user['org_id'];
        $sgIds = $this->SharingGroup->authorizedIds(
            $this->__user
        );

        return [
            'OR' => [
                // User's org owns the event
                'Event.org_id' => $userOrgId,
                // Distribution > 0 and not SG
                [
                    'Attribute.distribution >'
                        => 0,
                    'Attribute.distribution !='
                        => 4,
                ],
                // Distribution 4 with valid SG
                [
                    'Attribute.distribution'
                        => 4,
                    'Attribute.sharing_group_id'
                        => $sgIds,
                ],
            ],
        ];
    }

    /**
     * Fetch full detail for a single attribute.
     *
     * @param int $id Attribute ID.
     * @return array|null Attribute data or null.
     */
    private function __fetchAttributeDetail($id)
    {
        $attrs =
            $this->MispAttribute->fetchAttributes(
                $this->__user,
                [
                    'conditions' => [
                        'Attribute.id' => $id,
                    ],
                ]
            );
        return !empty($attrs[0])
            ? $attrs[0] : null;
    }

    /**
     * Add a new attribute to an event.
     *
     * Prompts for event ID and attribute fields,
     * then creates the attribute via captureAttribute.
     *
     * @return void
     */
    private function __addAttribute()
    {
        $eventId = $this->__resolveEventId();
        if ($eventId === null) {
            return;
        }
        $event = $this->Event->fetchSimpleEvent(
            $this->__user, $eventId
        );
        if (empty($event)) {
            $this->err(
                'Event #' . $eventId
                . ' not found.'
            );
            return;
        }
        if (!$this->__canModifyEvent($event)) {
            $this->err(
                'Permission denied: cannot modify '
                . 'this event.'
            );
            return;
        }
        $values = $this->__promptForFields(
            'attribute'
        );
        if ($values === false) {
            return;
        }
        if (
            !$this->__promptConfirm(
                'Create attribute in event #'
                . $eventId . '?'
            )
        ) {
            $this->out('Cancelled.');
            return;
        }
        $attribute = $values;
        $attribute['event_id'] = $eventId;
        $validationErrors = false;
        $this->MispAttribute->captureAttribute(
            $attribute,
            $eventId,
            $this->__user,
            false,
            false,
            $event,
            $validationErrors
        );
        if (empty($validationErrors)) {
            $this->out(
                'Attribute #'
                . $this->MispAttribute->id
                . ' created successfully.'
            );
            $this->Event->unpublishEvent(
                $eventId
            );
        } else {
            $this->err(
                'Failed to create attribute.'
            );
            if (is_array($validationErrors)) {
                foreach (
                    $validationErrors
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
            } else {
                $this->err(
                    '  ' . $validationErrors
                );
            }
        }
    }

    /**
     * Edit an existing attribute.
     *
     * Fetches current data, prompts for changes,
     * and saves updated fields.
     *
     * @param int $id Attribute ID.
     * @return void
     */
    private function __editAttribute($id)
    {
        $existing = $this->__fetchDetail(
            'attribute', $id
        );
        if (empty($existing)) {
            $this->err(
                'Attribute #' . $id
                . ' not found.'
            );
            return;
        }
        $eventId =
            $existing['Attribute']['event_id'];
        $event = $this->Event->fetchSimpleEvent(
            $this->__user, $eventId
        );
        if (empty($event)) {
            $this->err(
                'Parent event #' . $eventId
                . ' not found.'
            );
            return;
        }
        if (!$this->__canModifyEvent($event)) {
            $this->err(
                'Permission denied: cannot modify '
                . 'the parent event.'
            );
            return;
        }
        $editableFields =
            $this->__entityConfig['attribute']
                ['editableFields'];
        $values = $this->__promptForFields(
            'attribute',
            $existing['Attribute'],
            $editableFields
        );
        if ($values === false) {
            return;
        }
        if (
            !$this->__promptConfirm(
                'Save changes to attribute #'
                . $id . '?'
            )
        ) {
            $this->out('Cancelled.');
            return;
        }
        $data = [
            'Attribute' => array_merge(
                [
                    'id' => $id,
                    'event_id' => $eventId,
                    'uuid' =>
                        $existing['Attribute']
                            ['uuid'],
                    'category' =>
                        $existing['Attribute']
                            ['category'],
                    'type' =>
                        $existing['Attribute']
                            ['type'],
                    'value' =>
                        $existing['Attribute']
                            ['value'],
                ],
                $values
            ),
        ];
        $data['Attribute']['timestamp'] = time();
        $this->MispAttribute->id = $id;
        $result = $this->MispAttribute->save(
            $data,
            [
                'fieldList' => array_merge(
                    MispAttribute::EDITABLE_FIELDS,
                    ['event_id']
                ),
            ]
        );
        if ($result) {
            $this->out(
                'Attribute #' . $id
                . ' updated successfully.'
            );
            $this->Event->unpublishEvent(
                $eventId
            );
        } else {
            $this->err(
                'Failed to update attribute #'
                . $id . '.'
            );
            if (
                !empty(
                    $this->MispAttribute
                        ->validationErrors
                )
            ) {
                foreach (
                    $this->MispAttribute
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
     * Soft-delete an attribute by ID.
     *
     * Confirms with the user before performing
     * the deletion.
     *
     * @param int $id Attribute ID.
     * @return void
     */
    private function __deleteAttribute($id)
    {
        $attribute = $this->MispAttribute->find(
            'first',
            [
                'conditions' => [
                    'Attribute.id' => $id,
                ],
                'contain' => ['Event'],
                'recursive' => 0,
            ]
        );
        if (empty($attribute)) {
            $this->err(
                'Attribute #' . $id
                . ' not found.'
            );
            return;
        }
        if (
            !$this->__canModifyEvent($attribute)
        ) {
            $this->err(
                'Permission denied: cannot modify '
                . 'the parent event.'
            );
            return;
        }
        $desc = $attribute['Attribute']['type']
            . ' = '
            . $attribute['Attribute']['value'];
        if (mb_strlen($desc) > 60) {
            $desc = mb_substr($desc, 0, 57)
                . '...';
        }
        if (
            !$this->__promptConfirm(
                'Soft-delete attribute #' . $id
                . ' (' . $desc . ')?'
            )
        ) {
            $this->out('Cancelled.');
            return;
        }
        $result = $this->MispAttribute
            ->deleteAttribute(
                $id, $this->__user, false
            );
        if ($result) {
            $this->out(
                'Attribute #' . $id
                . ' soft-deleted successfully.'
            );
        } else {
            $this->err(
                'Failed to delete attribute #'
                . $id . '.'
            );
        }
    }
}
