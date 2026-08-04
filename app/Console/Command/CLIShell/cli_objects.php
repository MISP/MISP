<?php
/**
 * CLIObjectsTrait
 *
 * Provides object-specific entity configuration,
 * field metadata, and CRUD operations for CLIShell.
 */
trait CLIObjectsTrait
{
    /**
     * Get entity configuration for objects.
     *
     * @return array Entity config keyed by name.
     */
    private function __getObjectEntityConfig()
    {
        return [
            'object' => [
                'model' => 'MispObject',
                'alias' => 'Object',
                'aliases' => ['objects'],
                'listFields' => [
                    'id', 'event_id', 'name',
                    'meta-category', 'description',
                    'template_version',
                ],
                'editableFields' => [
                    'comment', 'distribution',
                    'sharing_group_id',
                ],
            ],
        ];
    }

    /**
     * Get field metadata for object entities.
     *
     * @return array Field meta keyed by entity
     *     then field name.
     */
    private function __getObjectFieldMeta()
    {
        return [
            'object' => [
                'comment' => [
                    'type' => 'string',
                    'required' => false,
                    'help' => 'Object comment',
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
            ],
        ];
    }

    /**
     * Fetch a paginated list of objects.
     *
     * @param array $filters Filter/pagination params.
     * @return array Flat rows for table display.
     */
    private function __fetchObjectList($filters)
    {
        $conditions = [
            'Object.deleted' => 0,
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
            $conditions['Object.event_id'] =
                $this->__context['id'];
        }

        if (isset($filters['object_name'])) {
            $conditions['Object.name'] =
                $filters['object_name'];
        }

        $isSiteAdmin = !empty(
            $this->__user['Role']
                ['perm_site_admin']
        );

        if (!$isSiteAdmin) {
            $conditions[] =
                $this->__objectAclConditions();
        }

        $findParams = [
            'conditions' => $conditions,
            'fields' => [
                'Object.id',
                'Object.event_id',
                'Object.name',
                'Object.meta-category',
                'Object.description',
                'Object.template_version',
            ],
            'recursive' => -1,
            'limit' => $limit,
            'page' => $page,
            'order' => [
                'Object.id' => isset(
                    $filters['sort_order']
                )
                ? $filters['sort_order'] : 'DESC',
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
                        . 'Object.event_id',
                    ],
                ],
            ];
        }

        $objects = $this->MispObject->find(
            'all', $findParams
        );

        $eventIds = array_column(
            array_column($objects, 'Object'),
            'event_id'
        );
        $this->__prefetchFK('event', $eventIds);

        $results = [];
        foreach ($objects as $obj) {
            $o = $obj['Object'];
            $results[] = [
                'id' => $o['id'],
                'event_id' => $this->__resolveFK(
                    'event', $o['event_id']
                ),
                'name' => $o['name'],
                'meta-category' =>
                    isset($o['meta-category'])
                    ? $o['meta-category'] : '',
                'description' =>
                    isset($o['description'])
                    ? $o['description'] : '',
                'template_version' =>
                    isset($o['template_version'])
                    ? $o['template_version'] : '',
            ];
        }

        return $results;
    }

    /**
     * Build ACL conditions for object queries.
     *
     * Non-admin users may not see objects with
     * distribution 0 on events they don't own, or
     * distribution 4 with unauthorised sharing groups.
     *
     * @return array CakePHP conditions array
     */
    private function __objectAclConditions()
    {
        $userOrgId = $this->__user['org_id'];
        $sgIds = $this->SharingGroup->authorizedIds(
            $this->__user
        );

        return [
            'OR' => [
                'Event.org_id' => $userOrgId,
                [
                    'Object.distribution >'
                        => 0,
                    'Object.distribution !='
                        => 4,
                ],
                [
                    'Object.distribution'
                        => 4,
                    'Object.sharing_group_id'
                        => $sgIds,
                ],
            ],
        ];
    }

    /**
     * Fetch full detail for a single object.
     *
     * @param int $id Object ID.
     * @return array|null Object data or null.
     */
    private function __fetchObjectDetail($id)
    {
        $objects = $this->MispObject->find(
            'first',
            [
                'conditions' => [
                    'Object.id' => $id,
                ],
                'contain' => [
                    'Event' => [
                        'fields' => [
                            'Event.id',
                            'Event.info',
                            'Event.org_id',
                        ],
                    ],
                    'Attribute' => [
                        'fields' => [
                            'Attribute.id',
                            'Attribute.type',
                            'Attribute.category',
                            'Attribute.value',
                            'Attribute.to_ids',
                            'Attribute.object_relation',
                        ],
                    ],
                    'SharingGroup' => [
                        'fields' => [
                            'SharingGroup.id',
                            'SharingGroup.name',
                        ],
                    ],
                ],
            ]
        );
        return !empty($objects) ? $objects : null;
    }

    /**
     * Add a new object interactively.
     *
     * Prompts for template name, looks up the
     * ObjectTemplate with its elements, iterates
     * through each element prompting for values,
     * then calls saveObject.
     *
     * @return void
     */
    private function __addObject()
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
        $this->out(
            'Enter object template name '
            . '(e.g. file, ip-port, domain-ip):'
        );
        $this->out('> ', 0);
        $line = fgets($this->__stdin);
        if ($line === false) {
            return;
        }
        $templateName = trim($line);
        if (empty($templateName)) {
            $this->err(
                'No template name provided.'
            );
            return;
        }
        $template = $this->MispObject
            ->ObjectTemplate->find('first', [
                'conditions' => [
                    'ObjectTemplate.name' =>
                        $templateName,
                    'ObjectTemplate.active' => 1,
                ],
                'order' => [
                    'ObjectTemplate.version'
                        => 'DESC',
                ],
                'contain' => [
                    'ObjectTemplateElement',
                ],
            ]);
        if (empty($template)) {
            $this->err(
                "Template '" . $templateName
                . "' not found or inactive."
            );
            return;
        }
        $this->out('');
        $this->out(
            'Template: '
            . $template['ObjectTemplate']['name']
            . ' v'
            . $template['ObjectTemplate']['version']
        );
        $this->out(
            $template['ObjectTemplate']
                ['description']
        );
        $this->out('');
        $this->out(
            'Fill in object attributes '
            . '(Enter to skip optional fields):'
        );
        $this->out('');
        $attributes = [];
        $requiredMissing = false;
        foreach (
            $template['ObjectTemplateElement']
            as $element
        ) {
            $isRequired = !empty(
                $element['required']
            );
            $label = '  '
                . $element['object_relation']
                . ' [' . $element['type'] . ']'
                . ($isRequired ? ' *' : '')
                . ': ';
            $this->out($label, 0);
            $valLine = fgets($this->__stdin);
            if ($valLine === false) {
                return;
            }
            $val = trim($valLine);
            if (empty($val) && $isRequired) {
                $this->err(
                    '  Required field "'
                    . $element['object_relation']
                    . '" cannot be empty.'
                );
                $requiredMissing = true;
                continue;
            }
            if (!empty($val)) {
                $attributes[] = [
                    'object_relation' =>
                        $element['object_relation'],
                    'type' => $element['type'],
                    'category' =>
                        !empty(
                            $element['category']
                        )
                        ? $element['category']
                        : 'Other',
                    'value' => $val,
                    'to_ids' =>
                        !empty(
                            $element['to_ids']
                        )
                        ? 1 : 0,
                    'distribution' => 5,
                ];
            }
        }
        if ($requiredMissing) {
            $this->err(
                'Aborted: required fields missing.'
            );
            return;
        }
        if (empty($attributes)) {
            $this->err(
                'No attributes provided, '
                . 'nothing to create.'
            );
            return;
        }
        $this->out('');
        $this->out(
            'Object will contain '
            . count($attributes)
            . ' attribute(s).'
        );
        if (!$this->__promptConfirm(
            'Create object in event #'
            . $eventId . '?'
        )) {
            $this->out('Cancelled.');
            return;
        }
        $object = [
            'Object' => [
                'distribution' =>
                    $event['Event']['distribution'],
                'sharing_group_id' =>
                    $event['Event']
                        ['sharing_group_id']
                    ?? 0,
                'comment' => '',
            ],
            'Attribute' => $attributes,
        ];
        $result = $this->MispObject->saveObject(
            $object,
            $eventId,
            $template,
            $this->__user
        );
        if (is_numeric($result)) {
            $this->out(
                'Object #' . $result
                . ' created successfully.'
            );
            $this->Event->unpublishEvent(
                $eventId
            );
        } else {
            $this->err(
                'Failed to create object.'
            );
            if (is_array($result)) {
                foreach (
                    $result as $field => $errs
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
     * Edit an existing object.
     *
     * @param int $id Object ID to edit.
     * @return void
     */
    private function __editObject($id)
    {
        $existing = $this->__fetchDetail(
            'object', $id
        );
        if (empty($existing)) {
            $this->err(
                'Object #' . $id . ' not found.'
            );
            return;
        }
        $eventId =
            $existing['Object']['event_id'];
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
            $this->__entityConfig['object']
                ['editableFields'];
        $values = $this->__promptForFields(
            'object',
            $existing['Object'],
            $editableFields
        );
        if ($values === false) {
            return;
        }
        if (
            !$this->__promptConfirm(
                'Save changes to object #'
                . $id . '?'
            )
        ) {
            $this->out('Cancelled.');
            return;
        }
        $data = [
            'MispObject' => array_merge(
                [
                    'id' => $id,
                    'uuid' =>
                        $existing['Object']
                            ['uuid'],
                    'event_id' => $eventId,
                ],
                $values
            ),
        ];
        $data['Object']['timestamp'] = time();
        $this->MispObject->id = $id;
        $result = $this->MispObject->save(
            $data,
            true,
            array_merge(
                $editableFields,
                ['timestamp']
            )
        );
        if ($result) {
            $this->out(
                'Object #' . $id
                . ' updated successfully.'
            );
            $this->Event->unpublishEvent(
                $eventId
            );
        } else {
            $this->err(
                'Failed to update object #'
                . $id . '.'
            );
            if (
                !empty(
                    $this->MispObject
                        ->validationErrors
                )
            ) {
                foreach (
                    $this->MispObject
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
     * Soft-delete an object and its attributes.
     *
     * @param int $id Object ID to delete.
     * @return void
     */
    private function __deleteObject($id)
    {
        $objects = $this->MispObject->fetchObjects(
            $this->__user,
            [
                'conditions' => [
                    'Object.id' => $id,
                ],
            ]
        );
        if (empty($objects)) {
            $this->err(
                'Object #' . $id . ' not found.'
            );
            return;
        }
        $object = $objects[0];
        $eventId =
            $object['Object']['event_id'];
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
        $name = $object['Object']['name']
            ?? '(unnamed)';
        if (
            !$this->__promptConfirm(
                'Soft-delete object #' . $id
                . " '" . $name . "' and all its "
                . 'attributes?'
            )
        ) {
            $this->out('Cancelled.');
            return;
        }
        $result = $this->MispObject->deleteObject(
            $object, false
        );
        if ($result !== false) {
            $this->out(
                'Object #' . $id
                . ' soft-deleted successfully.'
            );
        } else {
            $this->err(
                'Failed to delete object #'
                . $id . '.'
            );
        }
    }
}
