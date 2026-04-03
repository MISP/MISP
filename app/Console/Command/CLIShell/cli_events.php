<?php
/**
 * CLIEventsTrait - Event-specific functionality
 * for the MISP CLI shell.
 *
 * Provides entity configuration, field metadata,
 * and CRUD operations for Events.
 */
trait CLIEventsTrait
{
    /**
     * Get entity configuration for events.
     *
     * @return array Entity config keyed by name.
     */
    private function __getEventEntityConfig()
    {
        return [
            'event' => [
                'model' => 'Event',
                'aliases' => ['events'],
                'listFields' => [
                    'id', 'date', 'info',
                    'Orgc.name', 'threat_level_id',
                    'analysis', 'published',
                ],
                'editableFields' => [
                    'info', 'date', 'distribution',
                    'threat_level_id', 'analysis',
                    'sharing_group_id',
                ],
            ],
        ];
    }

    /**
     * Get field metadata for event fields.
     *
     * @return array Field metadata keyed by entity
     *               and field name.
     */
    private function __getEventFieldMeta()
    {
        return [
            'event' => [
                'info' => [
                    'type' => 'string',
                    'required' => true,
                    'help' => 'Event description/title',
                ],
                'date' => [
                    'type' => 'date',
                    'required' => false,
                    'help' => 'Event date (YYYY-MM-DD)',
                    'default' => 'today',
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
                    ],
                    'default' => '0',
                    'help' => 'Distribution level',
                ],
                'threat_level_id' => [
                    'type' => 'select',
                    'required' => false,
                    'options' => [
                        '1' => 'High',
                        '2' => 'Medium',
                        '3' => 'Low',
                        '4' => 'Undefined',
                    ],
                    'default' => '4',
                    'help' => 'Threat level',
                ],
                'analysis' => [
                    'type' => 'select',
                    'required' => false,
                    'options' => [
                        '0' => 'Initial',
                        '1' => 'Ongoing',
                        '2' => 'Completed',
                    ],
                    'default' => '0',
                    'help' => 'Analysis state',
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
     * Fetch a paginated list of events.
     *
     * @param array $filters Search/pagination filters.
     * @return array Flat rows for table display.
     */
    private function __fetchEventList($filters)
    {
        $params = [
            'minimal' => true,
            'limit' => isset($filters['limit'])
                ? (int)$filters['limit']
                : $this->__perPage,
            'page' => isset($filters['page'])
                ? (int)$filters['page'] : 1,
        ];

        $passthrough = [
            'value', 'type', 'category', 'org',
            'orgc_id', 'tags', 'searchall', 'from',
            'to', 'last', 'eventid', 'uuid',
            'published', 'threat_level_id', 'analysis',
            'timestamp', 'publish_timestamp', 'order',
        ];
        foreach ($passthrough as $key) {
            if (isset($filters[$key])) {
                $params[$key] = $filters[$key];
            }
        }

        if (
            isset($filters['sort_order'])
            && !isset($params['order'])
        ) {
            $params['order'] = 'Event.id '
                . $filters['sort_order'];
        }

        if (
            $this->__context['entity'] === 'event'
            && !empty($this->__context['id'])
            && !isset($params['eventid'])
        ) {
            $params['eventid'] =
                $this->__context['id'];
        }

        $eventIds = $this->Event->filterEventIds(
            $this->__user, $params
        );

        if (empty($eventIds)) {
            return [];
        }

        $ids = [];
        foreach ($eventIds as $row) {
            if (isset($row['Event']['id'])) {
                $ids[] = $row['Event']['id'];
            } elseif (is_numeric($row)) {
                $ids[] = $row;
            }
        }

        if (empty($ids)) {
            return [];
        }

        $events = $this->Event->find('all', [
            'conditions' => ['Event.id' => $ids],
            'fields' => [
                'Event.id', 'Event.date',
                'Event.info',
                'Event.threat_level_id',
                'Event.analysis',
                'Event.published',
                'Event.orgc_id',
            ],
            'contain' => [
                'Orgc' => [
                    'fields' => ['Orgc.name'],
                ],
            ],
            'order' => [
                'Event.id' => isset(
                    $filters['sort_order']
                )
                ? $filters['sort_order'] : 'DESC',
            ],
        ]);

        $results = [];
        foreach ($events as $event) {
            $results[] = [
                'id' => $event['Event']['id'],
                'date' => $event['Event']['date'],
                'info' => $event['Event']['info'],
                'Orgc.name' =>
                    isset($event['Orgc']['name'])
                    ? $event['Orgc']['name'] : '',
                'threat_level_id' =>
                    $event['Event']
                        ['threat_level_id'],
                'analysis' =>
                    $event['Event']['analysis'],
                'published' =>
                    $event['Event']['published']
                    ? 'Yes' : 'No',
            ];
        }

        return $results;
    }

    /**
     * Fetch detailed data for a single event.
     *
     * @param int $id Event ID.
     * @return array|null Event data or null.
     */
    private function __fetchEventDetail($id)
    {
        $events = $this->Event->fetchEvent(
            $this->__user,
            ['eventid' => $id, 'metadata' => true]
        );
        return !empty($events[0])
            ? $events[0] : null;
    }

    /**
     * Add a new event interactively.
     *
     * Prompts the user for field values, sets
     * defaults, and calls the Event model to create.
     *
     * @return void
     */
    private function __addEvent()
    {
        $values = $this->__promptForFields('event');
        if ($values === false) {
            return;
        }
        if (!$this->__promptConfirm('Create event?')) {
            $this->out('Cancelled.');
            return;
        }
        $data = ['Event' => $values];
        $data['Event']['user_id'] =
            $this->__user['id'];
        $data['Event']['org_id'] =
            $this->__user['Organisation']['id'];
        $data['Event']['orgc_id'] =
            $this->__user['Organisation']['id'];
        if (!isset($data['Event']['date'])) {
            $data['Event']['date'] = date('Y-m-d');
        }
        if (
            !isset($data['Event']['distribution'])
        ) {
            $data['Event']['distribution'] = '0';
        }
        if (
            !isset(
                $data['Event']['threat_level_id']
            )
        ) {
            $data['Event']['threat_level_id'] = '4';
        }
        if (!isset($data['Event']['analysis'])) {
            $data['Event']['analysis'] = '0';
        }
        $createdId = 0;
        $validationErrors = [];
        $result = $this->Event->_add(
            $data,
            false,
            $this->__user,
            0,
            null,
            false,
            null,
            $createdId,
            $validationErrors
        );
        if ($result === true) {
            $id = $createdId ?: $this->Event->id;
            $this->out(
                'Event #' . $id
                . ' created successfully.'
            );
        } else {
            $this->err('Failed to create event.');
            if (!empty($validationErrors)) {
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
            } elseif (is_string($result)) {
                $this->err('  ' . $result);
            }
        }
    }

    /**
     * Edit an existing event interactively.
     *
     * Fetches the event, checks permissions, prompts
     * for updated values, and saves changes.
     *
     * @param int $id Event ID to edit.
     * @return void
     */
    private function __editEvent($id)
    {
        $existing = $this->__fetchDetail(
            'event', $id
        );
        if (empty($existing)) {
            $this->err(
                'Event #' . $id . ' not found.'
            );
            return;
        }
        if (!$this->__canModifyEvent($existing)) {
            $this->err(
                'Permission denied: cannot modify '
                . 'this event.'
            );
            return;
        }
        $editableFields =
            $this->__entityConfig['event']
                ['editableFields'];
        $values = $this->__promptForFields(
            'event',
            $existing['Event'],
            $editableFields
        );
        if ($values === false) {
            return;
        }
        if (
            !$this->__promptConfirm(
                'Save changes to event #'
                . $id . '?'
            )
        ) {
            $this->out('Cancelled.');
            return;
        }
        $data = [
            'Event' => array_merge(
                ['id' => $id],
                $values
            ),
        ];
        $data['Event']['timestamp'] = time();
        $data['Event']['published'] = 0;
        $data['Event']['uuid'] =
            $existing['Event']['uuid'];
        if (!isset($data['Event']['info'])) {
            $data['Event']['info'] =
                $existing['Event']['info'];
        }
        $fieldList = array_merge(
            $editableFields,
            ['timestamp', 'published']
        );
        $this->Event->id = $id;
        $result = $this->Event->save(
            $data, true, $fieldList
        );
        if ($result) {
            $this->out(
                'Event #' . $id
                . ' updated successfully.'
            );
        } else {
            $this->err(
                'Failed to update event #'
                . $id . '.'
            );
            if (
                !empty(
                    $this->Event
                        ->validationErrors
                )
            ) {
                foreach (
                    $this->Event
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
     * Delete an event with confirmation.
     *
     * Checks existence, permissions, and prompts
     * for confirmation before deleting.
     *
     * @param int $id Event ID to delete.
     * @return void
     */
    private function __deleteEvent($id)
    {
        $event = $this->Event->find('first', [
            'conditions' => ['Event.id' => $id],
            'recursive' => -1,
        ]);
        if (empty($event)) {
            $this->err(
                'Event #' . $id . ' not found.'
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
        $info = $event['Event']['info']
            ?? '(no info)';
        if (mb_strlen($info) > 60) {
            $info = mb_substr($info, 0, 57)
                . '...';
        }
        if (
            !$this->__promptConfirm(
                'Delete event #' . $id
                . " '" . $info . "'?"
                . ' This cannot be undone.'
            )
        ) {
            $this->out('Cancelled.');
            return;
        }
        $result = $this->Event->quickDelete(
            $event
        );
        if ($result) {
            $this->out(
                'Event #' . $id
                . ' deleted successfully.'
            );
            if (
                $this->__context['entity']
                    === 'event'
                && (int)$this->__context['id']
                    === (int)$id
            ) {
                $this->__context = [
                    'entity' => null,
                    'id' => null,
                ];
                $this->out('Context cleared.');
            }
        } else {
            $this->err(
                'Failed to delete event #'
                . $id . '.'
            );
        }
    }
}
