<?php

/**
 * CLICommonTrait - Shared helper methods for the
 * MISP Interactive CLI Shell.
 *
 * Contains utility methods used across multiple entity
 * scopes (events, attributes, objects) including ACL
 * checks, field prompting, detail rendering, and
 * autocomplete support.
 *
 * Used by CLIShell via `use CLICommonTrait;`
 */
trait CLICommonTrait
{
    /**
     * Publish the impersonated account to both
     * audit engines, once, before any write.
     *
     * `CurrentUserId` is what AuditLog (the new
     * engine) and every other console shell use;
     * it also feeds the non-audit readers - tag
     * numerical-value overrides, workflow
     * initiator, analyst-data author - so they
     * see the impersonated user as the web would.
     * SysLogLogable (the default engine) takes the
     * same identity through its own static, which
     * it resolves at write time; setting it on the
     * loaded models' behaviour instances, as this
     * once did, was undone by the first lazy model
     * load, because the behaviour is a singleton
     * whose setup() rewrote the shared identity.
     *
     * @param array $user The impersonated user record
     * @return void
     */
    private function __setUserContext(array $user)
    {
        Configure::write('CurrentUserId', $user['id']);
        SysLogLogableBehavior::setShellUser($user);
    }

    /**
     * Check whether the current CLI user can modify
     * the given event. Mirrors the logic from
     * ACLComponent::canModifyEvent().
     *
     * @param array $event The event record with
     *                     Event.orgc_id and
     *                     Event.user_id
     * @return bool True if the user can modify
     */
    private function __canModifyEvent(array $event)
    {
        if (
            !empty(
                $this->__user['Role']['perm_site_admin']
            )
        ) {
            return true;
        }
        if (
            !empty(
                $this->__user['Role']['perm_modify_org']
            )
            && ($event['Event']['orgc_id'] ?? null)
                == $this->__user['org_id']
        ) {
            return true;
        }
        if (
            !empty(
                $this->__user['Role']['perm_modify']
            )
            && ($event['Event']['user_id'] ?? null)
                == $this->__user['id']
        ) {
            return true;
        }
        return false;
    }

    /**
     * Resolve an event ID from the current navigation
     * context or by prompting the user interactively.
     *
     * @return int|null The event ID, or null on failure
     */
    private function __resolveEventId()
    {
        if (
            $this->__context['entity'] === 'event'
            && !empty($this->__context['id'])
        ) {
            return (int)$this->__context['id'];
        }
        $this->out('Enter event ID: ', 0);
        $line = fgets($this->__stdin);
        if ($line === false) {
            return null;
        }
        $eventId = trim($line);
        if (!is_numeric($eventId)) {
            $this->err(
                "Invalid event ID: '"
                . $eventId . "'"
            );
            return null;
        }
        return (int)$eventId;
    }

    /**
     * Prompt for a single field value with type-aware
     * validation and default value handling.
     *
     * Supports types: string, select, boolean,
     * autocomplete, date, integer.
     *
     * @param string $fieldName The field name to prompt
     * @param array  $meta      Field metadata with keys:
     *                          type, required, help,
     *                          default, options, source
     * @param string|null $currentValue Current value
     *                                  for edit mode
     * @return string|null The entered value or null
     */
    private function __promptForField(
        $fieldName,
        $meta,
        $currentValue = null
    ) {
        $type = isset($meta['type'])
            ? $meta['type'] : 'string';
        $required = !empty($meta['required']);
        $help = isset($meta['help'])
            ? $meta['help'] : '';
        $default = isset($meta['default'])
            ? $meta['default'] : null;

        if ($default === 'today') {
            $default = date('Y-m-d');
        }

        $displayDefault = $currentValue !== null
            ? $currentValue : $default;

        $prompt = '  ' . $fieldName;
        if (!empty($help)) {
            $prompt .= ' (' . $help . ')';
        }
        if ($required) {
            $prompt .= ' *';
        }

        if ($type === 'select' && !empty($meta['options'])) {
            $this->out($prompt . ':');
            foreach ($meta['options'] as $k => $label) {
                $marker = ($displayDefault === (string)$k)
                    ? ' <-- default' : '';
                $this->out(
                    '    [' . $k . '] ' . $label . $marker
                );
            }
            $hint = $displayDefault !== null
                ? ' [' . $displayDefault . ']' : '';
            $this->out(
                '  Enter choice' . $hint . ': ', 0
            );
        } elseif ($type === 'boolean') {
            $hint = $displayDefault !== null
                ? ' [' . $displayDefault . ']' : '';
            $this->out(
                $prompt . ' (0/1)' . $hint . ': ', 0
            );
        } elseif (
            $type === 'autocomplete'
            && !empty($meta['source'])
        ) {
            $values = $this->__getAutocompleteValues(
                $meta['source']
            );
            $hint = '';
            if (!empty($values)) {
                $preview = array_slice($values, 0, 5);
                $hint = ' (e.g. '
                    . implode(', ', $preview) . ', ...)';
            }
            $defHint = $displayDefault !== null
                ? ' [' . $displayDefault . ']' : '';
            $this->out(
                $prompt . $hint . $defHint . ': ', 0
            );
        } else {
            $hint = $displayDefault !== null
                ? ' [' . $displayDefault . ']' : '';
            $this->out($prompt . $hint . ': ', 0);
        }

        $line = fgets($this->__stdin);
        if ($line === false) {
            return null;
        }
        $input = trim($line);

        if ($input === '' && $displayDefault !== null) {
            return (string)$displayDefault;
        }
        if ($input === '' && $required) {
            $this->err(
                '  Field "' . $fieldName . '" is required.'
            );
            return $this->__promptForField(
                $fieldName, $meta, $currentValue
            );
        }
        if ($input === '' && !$required) {
            return null;
        }

        if (
            $type === 'select'
            && !empty($meta['options'])
            && !isset($meta['options'][$input])
        ) {
            $this->err(
                '  Invalid choice. Valid options: '
                . implode(
                    ', ',
                    array_keys($meta['options'])
                )
            );
            return $this->__promptForField(
                $fieldName, $meta, $currentValue
            );
        }

        if (
            $type === 'boolean'
            && !in_array($input, ['0', '1'], true)
        ) {
            $this->err('  Please enter 0 or 1.');
            return $this->__promptForField(
                $fieldName, $meta, $currentValue
            );
        }

        if (
            $type === 'date'
            && !preg_match(
                '/^\d{4}-\d{2}-\d{2}$/', $input
            )
        ) {
            $this->err(
                '  Invalid date format. Use YYYY-MM-DD.'
            );
            return $this->__promptForField(
                $fieldName, $meta, $currentValue
            );
        }

        if (
            $type === 'integer'
            && !is_numeric($input)
        ) {
            $this->err('  Please enter a number.');
            return $this->__promptForField(
                $fieldName, $meta, $currentValue
            );
        }

        return $input;
    }

    /**
     * Prompt for all fields of a given entity type,
     * optionally pre-filling with current values for
     * edit mode.
     *
     * @param string     $entity  Entity type name
     *                            (e.g. 'event')
     * @param array|null $current Current record values
     *                            for edit mode
     * @param array|null $fields  Specific fields to
     *                            prompt for, or null
     *                            for all
     * @return array|false Field values, or false if
     *                     no changes entered
     */
    private function __promptForFields(
        $entity,
        $current = null,
        $fields = null
    ) {
        if (!isset($this->__fieldMeta[$entity])) {
            $this->err(
                'No field metadata for ' . $entity . '.'
            );
            return false;
        }

        $meta = $this->__fieldMeta[$entity];
        if ($fields === null) {
            $fields = array_keys($meta);
        }

        $isEdit = $current !== null;
        $this->out('');
        $this->out(
            ($isEdit ? 'Edit' : 'Add') . ' '
            . ucfirst($entity)
            . ' - fill in fields'
            . ($isEdit
                ? ' (Enter to keep current value)'
                : ' (* = required)')
            . ':'
        );
        $this->out('');

        $values = [];
        foreach ($fields as $field) {
            if (!isset($meta[$field])) {
                continue;
            }
            $currentVal = null;
            if (
                $isEdit
                && array_key_exists($field, $current)
            ) {
                $fType = isset($meta[$field]['type'])
                    ? $meta[$field]['type'] : 'string';
                if ($fType === 'boolean') {
                    $currentVal = !empty(
                        $current[$field]
                    ) ? '1' : '0';
                } else {
                    $currentVal =
                        (string)$current[$field];
                }
            }
            $val = $this->__promptForField(
                $field, $meta[$field], $currentVal
            );
            if ($val !== null) {
                $values[$field] = $val;
            }
        }

        if (empty($values)) {
            $this->out('  No changes entered.');
            return false;
        }

        return $values;
    }

    /**
     * Prompt the user for a yes/no confirmation.
     *
     * @param string $message The confirmation message
     * @return bool True if user confirmed with y/yes
     */
    private function __promptConfirm($message)
    {
        $this->out($message . ' [y/N]: ', 0);
        $line = fgets($this->__stdin);
        if ($line === false) {
            return false;
        }
        $input = strtolower(trim($line));
        return $input === 'y' || $input === 'yes';
    }

    /**
     * Retrieve autocomplete values for a given field
     * source identifier.
     *
     * @param string $source The autocomplete source
     *                       name (e.g. 'attributeTypes',
     *                       'attributeCategories')
     * @return array List of valid values
     */
    private function __getAutocompleteValues($source)
    {
        if ($source === 'attributeTypes') {
            if (
                property_exists(
                    $this->MispAttribute,
                    'typeDefinitions'
                )
            ) {
                return array_keys(
                    $this->MispAttribute->typeDefinitions
                );
            }
            return [];
        }

        if ($source === 'attributeCategories') {
            if (
                property_exists(
                    $this->MispAttribute,
                    'categoryDefinitions'
                )
            ) {
                return array_keys(
                    $this->MispAttribute
                        ->categoryDefinitions
                );
            }
            return [];
        }

        return [];
    }

    /**
     * Render a detailed view of a single record,
     * showing all scalar fields and any associative
     * sub-sections.
     *
     * @param string $entity The entity type name
     * @param array  $record The full record array
     * @return void
     */
    private function __renderDetail($entity, $record)
    {
        $this->out('');

        $alias = $this->__modelAlias($entity);

        if (isset($record[$alias])) {
            $data = $record[$alias];
        } elseif (isset($record[ucfirst($entity)])) {
            $data = $record[ucfirst($entity)];
        } elseif (isset($record['Event'])) {
            $data = $record['Event'];
        } else {
            $data = $record;
        }

        $maxKeyLen = 0;
        foreach ($data as $key => $value) {
            if (is_array($value)) {
                continue;
            }
            if (strlen($key) > $maxKeyLen) {
                $maxKeyLen = strlen($key);
            }
        }

        $this->out(
            '=== ' . ucfirst($entity) . ' Detail ==='
        );
        $this->out('');

        $fkMap = [
            'org_id' => 'org',
            'orgc_id' => 'org',
            'event_id' => 'event',
            'role_id' => 'role',
            'sharing_group_id' => 'sharing_group',
            'object_id' => 'object',
        ];

        foreach ($data as $key => $value) {
            if (is_array($value)) {
                continue;
            }
            $display = (string)$value;
            if (
                isset($fkMap[$key])
                && !empty($value)
            ) {
                $display = $this->__resolveFK(
                    $fkMap[$key], $value
                );
            }
            $paddedKey = str_pad($key, $maxKeyLen);
            $this->out(
                '  ' . $paddedKey . ' : ' . $display
            );
        }

        foreach ($record as $section => $sectionData) {
            if ($section === $alias) {
                continue;
            }
            if ($section === ucfirst($entity)) {
                continue;
            }
            if ($section === 'Event') {
                continue;
            }
            if (!is_array($sectionData)) {
                continue;
            }
            if ($this->__isAssocArray($sectionData)) {
                $this->out('');
                $this->out('  [' . $section . ']');
                foreach ($sectionData as $k => $v) {
                    if (is_array($v)) {
                        continue;
                    }
                    $this->out('    ' . $k . ': ' . $v);
                }
            }
        }

        $this->out('');
    }

    /**
     * Get a human-readable display label for a
     * database field name.
     *
     * @param string $field The field name
     * @return string The display label
     */
    private function __fieldLabel($field)
    {
        $labels = [
            'id' => 'ID',
            'event_id' => 'Event',
            'date' => 'Date',
            'info' => 'Info',
            'Orgc.name' => 'Org Creator',
            'threat_level_id' => 'Threat Level',
            'analysis' => 'Analysis',
            'published' => 'Published',
            'distribution' => 'Distribution',
            'sharing_group_id' => 'Sharing Group',
            'type' => 'Type',
            'category' => 'Category',
            'value' => 'Value',
            'to_ids' => 'To IDS',
            'comment' => 'Comment',
            'name' => 'Name',
            'colour' => 'Colour',
            'exportable' => 'Exportable',
            'hide_tag' => 'Hidden',
            'email' => 'Email',
            'org_id' => 'Org ID',
            'orgc_id' => 'Org Creator ID',
            'role_id' => 'Role ID',
            'disabled' => 'Disabled',
            'uuid' => 'UUID',
            'nationality' => 'Country',
            'sector' => 'Sector',
            'local' => 'Local',
            'contacts' => 'Contacts',
            'url' => 'URL',
            'push' => 'Push',
            'pull' => 'Pull',
            'provider' => 'Provider',
            'enabled' => 'Enabled',
            'active' => 'Active',
            'description' => 'Description',
            'namespace' => 'Namespace',
            'version' => 'Version',
            'meta-category' => 'Meta Category',
            'template_version' => 'Tpl Version',
            'permission' => 'Permission',
            'perm_site_admin' => 'Site Admin',
            'perm_admin' => 'Org Admin',
            'perm_sync' => 'Sync',
            'perm_audit' => 'Audit',
            'perm_auth' => 'Auth Key',
            'perm_tagger' => 'Tagger',
            'perm_tag_editor' => 'Tag Editor',
            'perm_sharing_group' => 'Sharing Grp',
            'perm_sighting' => 'Sighting',
            'perm_delegate' => 'Delegate',
            'perm_template' => 'Template',
            'perm_galaxy_editor' => 'Galaxy Editor',
            'perm_warninglist' => 'Warninglist',
            'perm_publish_zmq' => 'ZMQ Pub',
            'perm_publish_kafka' => 'Kafka Pub',
            'perm_analyst_data' => 'Analyst Data',
            'enforce_rate_limit' => 'Rate Limit',
            'rate_limit_count' => 'Rate Count',
            'max_execution_time' => 'Max Exec Time',
            'memory_limit' => 'Memory Limit',
            'change_pw' => 'Change PW',
            'autoalert' => 'Auto Alert',
            'contactalert' => 'Contact Alert',
            'object_relation' => 'Relation',
            'first_seen' => 'First Seen',
            'last_seen' => 'Last Seen',
            'timestamp' => 'Timestamp',
            'created_by' => 'Created By',
        ];

        return isset($labels[$field])
            ? $labels[$field] : $field;
    }

    /**
     * Check whether an array is associative (string
     * keys) rather than sequential numeric keys.
     *
     * @param mixed $arr The array to check
     * @return bool True if associative
     */
    private function __isAssocArray($arr)
    {
        if (empty($arr) || !is_array($arr)) {
            return false;
        }
        return array_keys($arr) !== range(
            0, count($arr) - 1
        );
    }

    /**
     * Get the CakePHP alias for an entity's model.
     *
     * Most models use their class name as alias,
     * but MispObject uses 'Object'. The alias is
     * the key CakePHP uses in result arrays.
     *
     * @param string $entity Entity name
     * @return string The model alias
     */
    private function __modelAlias($entity)
    {
        $config = $this->__entityConfig[$entity];
        if (!empty($config['alias'])) {
            return $config['alias'];
        }
        return $config['model'];
    }

    /** @var array Cache for FK label lookups */
    private $__fkCache = [];

    /**
     * Resolve a foreign key ID to "[id] label".
     *
     * Caches results to avoid repeated queries.
     * Returns "[id]" if the record is not found.
     *
     * @param string $type FK type (event, org, role,
     *   user, object, galaxy_cluster)
     * @param int $id The foreign key ID
     * @return string Formatted "[id] label"
     */
    private function __resolveFK($type, $id)
    {
        if (empty($id)) {
            return '';
        }
        $cacheKey = $type . ':' . $id;
        if (isset($this->__fkCache[$cacheKey])) {
            return $this->__fkCache[$cacheKey];
        }

        $label = null;
        switch ($type) {
            case 'event':
                $r = $this->Event->find('first', [
                    'conditions' => [
                        'Event.id' => $id,
                    ],
                    'fields' => ['Event.info'],
                    'recursive' => -1,
                ]);
                if (!empty($r)) {
                    $label = $r['Event']['info'];
                }
                break;

            case 'org':
                $r = $this->Organisation->find(
                    'first',
                    [
                        'conditions' => [
                            'Organisation.id' => $id,
                        ],
                        'fields' => [
                            'Organisation.name',
                        ],
                        'recursive' => -1,
                    ]
                );
                if (!empty($r)) {
                    $label =
                        $r['Organisation']['name'];
                }
                break;

            case 'role':
                $r = $this->Role->find('first', [
                    'conditions' => [
                        'Role.id' => $id,
                    ],
                    'fields' => ['Role.name'],
                    'recursive' => -1,
                ]);
                if (!empty($r)) {
                    $label = $r['Role']['name'];
                }
                break;

            case 'user':
                $r = $this->User->find('first', [
                    'conditions' => [
                        'User.id' => $id,
                    ],
                    'fields' => ['User.email'],
                    'recursive' => -1,
                ]);
                if (!empty($r)) {
                    $label = $r['User']['email'];
                }
                break;

            case 'object':
                $r = $this->MispObject->find(
                    'first',
                    [
                        'conditions' => [
                            'Object.id' => $id,
                        ],
                        'fields' => [
                            'Object.name',
                        ],
                        'recursive' => -1,
                    ]
                );
                if (!empty($r)) {
                    $label = $r['Object']['name'];
                }
                break;

            case 'galaxy_cluster':
                $r = $this->GalaxyCluster->find(
                    'first',
                    [
                        'conditions' => [
                            'GalaxyCluster.id'
                                => $id,
                        ],
                        'fields' => [
                            'GalaxyCluster.value',
                        ],
                        'recursive' => -1,
                    ]
                );
                if (!empty($r)) {
                    $label =
                        $r['GalaxyCluster']['value'];
                }
                break;

            case 'sharing_group':
                $r = $this->SharingGroup->find(
                    'first',
                    [
                        'conditions' => [
                            'SharingGroup.id'
                                => $id,
                        ],
                        'fields' => [
                            'SharingGroup.name',
                        ],
                        'recursive' => -1,
                    ]
                );
                if (!empty($r)) {
                    $label =
                        $r['SharingGroup']['name'];
                }
                break;
        }

        $result = $label !== null
            ? '[' . $id . '] ' . $label
            : '[' . $id . ']';
        $this->__fkCache[$cacheKey] = $result;
        return $result;
    }

    /**
     * Batch-resolve foreign key IDs for a result set.
     *
     * Pre-populates the FK cache with a single query
     * per FK type, then applies __resolveFK to each
     * row. Call this before iterating results.
     *
     * @param string $type FK type
     * @param array $ids Unique IDs to resolve
     * @return void
     */
    private function __prefetchFK($type, $ids)
    {
        $ids = array_unique(array_filter($ids));
        if (empty($ids)) {
            return;
        }

        // Remove already cached
        $needed = [];
        foreach ($ids as $id) {
            $key = $type . ':' . $id;
            if (!isset($this->__fkCache[$key])) {
                $needed[] = $id;
            }
        }
        if (empty($needed)) {
            return;
        }

        $map = [
            'event' => [
                'Event', 'Event.id',
                'Event.info', 'info',
            ],
            'org' => [
                'Organisation',
                'Organisation.id',
                'Organisation.name', 'name',
            ],
            'role' => [
                'Role', 'Role.id',
                'Role.name', 'name',
            ],
            'user' => [
                'User', 'User.id',
                'User.email', 'email',
            ],
            'sharing_group' => [
                'SharingGroup',
                'SharingGroup.id',
                'SharingGroup.name', 'name',
            ],
        ];

        if (!isset($map[$type])) {
            return;
        }

        list($model, $idField, $labelField, $key)
            = $map[$type];
        $alias = explode('.', $idField)[0];

        $records = $this->{$model}->find('all', [
            'conditions' => [
                $idField => $needed,
            ],
            'fields' => [$idField, $labelField],
            'recursive' => -1,
        ]);

        foreach ($records as $rec) {
            $rid = $rec[$alias]['id'];
            $val = $rec[$alias][$key];
            $cacheKey = $type . ':' . $rid;
            $this->__fkCache[$cacheKey] =
                '[' . $rid . '] ' . $val;
        }

        // Mark not-found IDs so we don't re-query
        foreach ($needed as $id) {
            $cacheKey = $type . ':' . $id;
            if (!isset($this->__fkCache[$cacheKey])) {
                $this->__fkCache[$cacheKey] =
                    '[' . $id . ']';
            }
        }
    }

    /**
     * Neutralise terminal control sequences in a
     * value before it reaches the terminal.
     *
     * Everything the shell prints comes from the
     * database and is attacker-controlled: any
     * perm_add user can store an attribute whose
     * value carries ESC[ sequences, and the core
     * validator only rejects values made entirely
     * of control characters. C0 controls, DEL and
     * the C1 range are rewritten in cat -v caret
     * notation so an analyst can still see that an
     * indicator carries them; tab and newlines
     * become spaces so the table layout holds; the
     * Unicode bidi overrides and isolates are
     * spelled out so a right-to-left override
     * cannot make one indicator read as another.
     *
     * Applied by out()/err() to everything the
     * shell prints, and by the list fetchers and
     * detail-row builder before width math so the
     * columns are sized on what is displayed.
     *
     * @param mixed $value Value to print
     * @return mixed Sanitised copy (arrays mapped)
     */
    private function __term($value)
    {
        if (is_array($value)) {
            return array_map([$this, '__term'], $value);
        }
        if ($value === null || $value === '') {
            return $value;
        }
        $str = (string)$value;
        // Fast path: no C0/DEL byte, no lead byte of
        // the C1 (\xC2) or bidi (\xE2) code points -
        // return the original unchanged, so a clean
        // integer id stays an integer.
        if (!preg_match('/[\x00-\x1F\x7F\xC2\xE2]/', $str)) {
            return $value;
        }
        $value = $str;
        $caret = function ($cp) {
            if ($cp === 0x09 || $cp === 0x0A || $cp === 0x0D) {
                return ' ';
            }
            if ($cp < 0x20) {
                return '^' . chr($cp + 0x40);
            }
            if ($cp === 0x7F) {
                return '^?';
            }
            if ($cp <= 0x9F) {
                return 'M-^' . chr($cp - 0x80 + 0x40);
            }
            return sprintf('<U+%04X>', $cp);
        };
        $out = preg_replace_callback(
            '/[\x{00}-\x{1F}\x{7F}\x{80}-\x{9F}'
            . '\x{202A}-\x{202E}\x{2066}-\x{2069}]/u',
            function ($m) use ($caret) {
                return $caret(mb_ord($m[0], 'UTF-8'));
            },
            $value
        );
        if ($out === null) {
            // Not valid UTF-8: byte-level C0/DEL only.
            $out = preg_replace_callback(
                '/[\x00-\x1F\x7F]/',
                function ($m) use ($caret) {
                    return $caret(ord($m[0]));
                },
                $value
            );
        }
        return $out;
    }

    /**
     * Sanitise every scalar cell of a list result.
     *
     * @param array $rows List rows
     * @return array
     */
    private function __termRows(array $rows)
    {
        foreach ($rows as &$row) {
            foreach ($row as $k => $v) {
                if (!is_array($v)) {
                    $row[$k] = $this->__term($v);
                }
            }
        }
        unset($row);
        return $rows;
    }

    /**
     * Whether the CLI user may perform a write
     * operation on an entity, mirroring the web ACL.
     *
     * Site admins always may. `adminOnly` and
     * `writeAdminOnly` entities refuse everyone
     * else. `writePerms` names the role flag needed
     * per operation (add/edit/delete). An entity
     * with none of these is writable by anyone,
     * subject to the per-record checks (such as
     * __canModifyEvent()) its own add/edit/delete
     * code performs.
     *
     * @param string $entity Entity name
     * @param string $op     add|edit|delete
     * @return bool
     */
    private function __canWriteEntity($entity, $op)
    {
        $config = $this->__entityConfig[$entity];
        $role = $this->__user['Role'];
        if (!empty($role['perm_site_admin'])) {
            return true;
        }
        if (
            !empty($config['adminOnly'])
            || !empty($config['writeAdminOnly'])
        ) {
            return false;
        }
        if (!empty($config['writePerms'][$op])) {
            $flag = $config['writePerms'][$op];
            return !empty($role[$flag]);
        }
        return true;
    }

    /**
     * Print the permission-denied message for a
     * refused write, naming what the user lacks.
     *
     * @param string $entity Entity name
     * @param string $op     add|edit|delete
     * @return void
     */
    private function __denyWrite($entity, $op)
    {
        $config = $this->__entityConfig[$entity];
        $need = 'site admin access';
        if (
            empty($config['adminOnly'])
            && empty($config['writeAdminOnly'])
            && !empty($config['writePerms'][$op])
            && $config['writePerms'][$op]
                !== 'perm_site_admin'
        ) {
            $need = 'the '
                . $config['writePerms'][$op]
                . ' permission';
        }
        $this->err(
            'Permission denied: ' . $op . ' '
            . $entity . ' requires ' . $need . '.'
        );
    }

    /**
     * Columns to fetch for an entity's detail view:
     * the model's schema minus the entity's
     * `hiddenFields`, so a secret column is never
     * read from the database rather than read and
     * blanked afterwards.
     *
     * @param string $entity Entity name
     * @return array Alias-qualified field list
     */
    private function __detailFields($entity)
    {
        $config = $this->__entityConfig[$entity];
        $model = $this->{$config['model']};
        $alias = $this->__modelAlias($entity);
        $hidden = !empty($config['hiddenFields'])
            ? $config['hiddenFields'] : [];
        $fields = [];
        foreach (array_keys($model->schema()) as $col) {
            if (!in_array($col, $hidden, true)) {
                $fields[] = $alias . '.' . $col;
            }
        }
        return $fields;
    }

    /**
     * Clamp pagination to a sane range: a limit
     * that is missing, non-numeric or below 1
     * becomes the default page size, anything
     * above $__maxPerPage is capped there, and
     * page is at least 1. A limit of 0, a negative
     * or a non-numeric value used to make
     * DboSource drop the LIMIT clause entirely and
     * return the whole table.
     *
     * @param array $filters Parsed filters
     * @return array Filters with limit/page clamped
     */
    private function __normalisePagination(
        array $filters
    ) {
        $limit = isset($filters['limit'])
            && is_numeric($filters['limit'])
            ? (int)$filters['limit'] : 0;
        if ($limit < 1) {
            $limit = $this->__perPage;
        }
        $filters['limit'] = min(
            $this->__maxPerPage, $limit
        );
        $page = isset($filters['page'])
            && is_numeric($filters['page'])
            ? (int)$filters['page'] : 1;
        $filters['page'] = max(1, $page);
        return $filters;
    }

    /**
     * Warn about filter keys the entity does not
     * implement rather than silently discarding
     * them - `list attribute value=%evil%` used to
     * return everything with no hint that the
     * filter had been ignored.
     *
     * @param string $entity  Entity name
     * @param array  $filters Parsed filters
     * @return void
     */
    private function __warnUnsupportedFilters(
        $entity,
        array $filters
    ) {
        $config = $this->__entityConfig[$entity];
        $supported = array_merge(
            ['limit', 'page', 'sort_order'],
            !empty($config['filters'])
                ? $config['filters'] : []
        );
        $unknown = array_diff(
            array_keys($filters), $supported
        );
        if (!empty($unknown)) {
            $this->err(
                'Ignoring unsupported filter(s) for '
                . $entity . ': '
                . implode(', ', $unknown)
            );
        }
    }
}
