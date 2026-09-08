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
                'filters' => [
                    'eventid', 'type', 'category',
                    'to_ids', 'searchall', 'value',
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
        $conditions = [];
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
        if (isset($filters['value'])) {
            // Documented as a LIKE match: the
            // caller supplies the wildcards.
            $conditions['Attribute.value LIKE'] =
                $filters['value'];
        }

        // fetchAttributes() applies the same
        // event + object + attribute visibility
        // rule as the web, joins the parent event
        // and excludes soft-deleted rows itself.
        $attributes =
            $this->MispAttribute->fetchAttributes(
                $this->__user,
                [
                    'conditions' => $conditions,
                    'flatten' => 1,
                    'limit' => $limit,
                    'page' => $page,
                    'order' => 'Attribute.id '
                        . (isset($filters['sort_order'])
                            ? $filters['sort_order']
                            : 'DESC'),
                ]
            );

        $results = [];
        foreach ($attributes as $attr) {
            $a = $attr['Attribute'];
            $results[] = [
                'id' => $a['id'],
                'event_id' => '[' . $a['event_id']
                    . '] '
                    . ($attr['Event']['info'] ?? ''),
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
    private function __editAttribute($id, $fields = null)
    {
        $existing = $this->__fetchDetail(
            'attribute', $id
        );
        if (empty($existing)) {
            $this->err(
                'Attribute #' . $id
                . ' not found.'
            );
            return false;
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
            return false;
        }
        if (!$this->__canModifyEvent($event)) {
            $this->err(
                'Permission denied: cannot modify '
                . 'the parent event.'
            );
            return false;
        }
        $editableFields =
            $this->__entityConfig['attribute']
                ['editableFields'];
        if ($fields !== null) {
            $editableFields = array_values(
                array_intersect(
                    $editableFields, $fields
                )
            );
        }
        $values = $this->__promptForFields(
            'attribute',
            $existing['Attribute'],
            $editableFields
        );
        if ($values === false) {
            return false;
        }
        if (
            !$this->__promptConfirm(
                'Save changes to attribute #'
                . $id . '?'
            )
        ) {
            $this->out('Cancelled.');
            return false;
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
            return true;
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
        return false;
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
        // Resolve through the ACL'd accessor so a
        // record the user cannot see reads exactly
        // like one that does not exist.
        $attribute = $this->__fetchAttributeDetail(
            $id
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
