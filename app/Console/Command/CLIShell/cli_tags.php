<?php
/**
 * CLITagsTrait
 *
 * Provides tag-specific entity configuration,
 * field metadata, and CRUD operations for CLIShell.
 */
trait CLITagsTrait
{
    /**
     * Get entity configuration for tags.
     *
     * @return array Entity config keyed by name.
     */
    private function __getTagEntityConfig()
    {
        return [
            'tag' => [
                'model' => 'Tag',
                'aliases' => ['tags'],
                'listFields' => [
                    'id', 'name', 'colour',
                    'exportable', 'hide_tag',
                ],
                'editableFields' => [
                    'name', 'colour', 'exportable',
                    'hide_tag', 'local_only',
                    'numerical_value',
                ],
            ],
        ];
    }

    /**
     * Get field metadata for tag prompts.
     *
     * @return array Field metadata keyed by entity.
     */
    private function __getTagFieldMeta()
    {
        return [
            'tag' => [
                'name' => [
                    'type' => 'string',
                    'required' => true,
                    'help' => 'Tag name '
                        . '(e.g. tlp:white)',
                ],
                'colour' => [
                    'type' => 'string',
                    'required' => false,
                    'help' => 'Colour (#RRGGBB, '
                        . 'auto-generated if empty)',
                ],
                'exportable' => [
                    'type' => 'boolean',
                    'required' => false,
                    'default' => '1',
                    'help' => 'Exportable (0/1)',
                ],
                'hide_tag' => [
                    'type' => 'boolean',
                    'required' => false,
                    'default' => '0',
                    'help' => 'Hidden (0/1)',
                ],
                'local_only' => [
                    'type' => 'boolean',
                    'required' => false,
                    'default' => '0',
                    'help' => 'Local only (0/1)',
                ],
                'numerical_value' => [
                    'type' => 'integer',
                    'required' => false,
                    'help' => 'Numerical value',
                ],
            ],
        ];
    }

    /**
     * Fetch a paginated list of tags.
     *
     * @param array $filters Search filters.
     * @return array Formatted tag rows.
     */
    private function __fetchTagList($filters)
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
            $eventTags = $this->EventTag->find(
                'list',
                [
                    'conditions' => [
                        'EventTag.event_id' =>
                            $this->__context['id'],
                    ],
                    'fields' => [
                        'EventTag.tag_id',
                    ],
                ]
            );
            if (empty($eventTags)) {
                return [];
            }
            $conditions['Tag.id'] =
                array_values($eventTags);
        }

        if (isset($filters['searchall'])) {
            $conditions['Tag.name LIKE'] =
                '%' . $filters['searchall'] . '%';
        }

        $tags = $this->Tag->find('all', [
            'conditions' => $conditions,
            'fields' => [
                'Tag.id', 'Tag.name',
                'Tag.colour', 'Tag.exportable',
                'Tag.hide_tag',
            ],
            'recursive' => -1,
            'limit' => $limit,
            'page' => $page,
            'order' => [
                'Tag.name' => isset(
                    $filters['sort_order']
                )
                ? $filters['sort_order'] : 'ASC',
            ],
        ]);

        $results = [];
        foreach ($tags as $tag) {
            $t = $tag['Tag'];
            $results[] = [
                'id' => $t['id'],
                'name' => $t['name'],
                'colour' => $t['colour'],
                'exportable' => !empty(
                    $t['exportable']
                ) ? 'Yes' : 'No',
                'hide_tag' => !empty(
                    $t['hide_tag']
                ) ? 'Yes' : 'No',
            ];
        }

        return $results;
    }

    /**
     * Fetch full detail for a single tag.
     *
     * @param int $id Tag ID.
     * @return array|null Tag data or null.
     */
    private function __fetchTagDetail($id)
    {
        return $this->Tag->find('first', [
            'conditions' => ['Tag.id' => $id],
            'recursive' => -1,
        ]);
    }

    /**
     * Add a new tag interactively.
     *
     * @return void
     */
    private function __addTag()
    {
        $values = $this->__promptForFields('tag');
        if ($values === false) {
            return;
        }
        if (
            !$this->__promptConfirm('Create tag?')
        ) {
            $this->out('Cancelled.');
            return;
        }

        if (
            empty($values['colour'])
            && !empty($values['name'])
        ) {
            $values['colour'] = $this->Tag
                ->tagColor($values['name']);
        }

        $this->Tag->create();
        $result = $this->Tag->save(
            ['Tag' => $values]
        );
        if ($result) {
            $this->out(
                'Tag #' . $this->Tag->id
                . ' created successfully.'
            );
        } else {
            $this->err('Failed to create tag.');
            if (
                !empty(
                    $this->Tag->validationErrors
                )
            ) {
                foreach (
                    $this->Tag->validationErrors
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
     * Edit an existing tag interactively.
     *
     * @param int $id Tag ID.
     * @return void
     */
    private function __editTag($id)
    {
        $existing = $this->__fetchTagDetail($id);
        if (empty($existing)) {
            $this->err(
                'Tag #' . $id . ' not found.'
            );
            return;
        }
        $editableFields =
            $this->__entityConfig['tag']
                ['editableFields'];
        $values = $this->__promptForFields(
            'tag',
            $existing['Tag'],
            $editableFields
        );
        if ($values === false) {
            return;
        }
        if (
            !$this->__promptConfirm(
                'Save changes to tag #'
                . $id . '?'
            )
        ) {
            $this->out('Cancelled.');
            return;
        }
        $data = [
            'Tag' => array_merge(
                ['id' => $id],
                $values
            ),
        ];
        $this->Tag->id = $id;
        $result = $this->Tag->save($data);
        if ($result) {
            $this->out(
                'Tag #' . $id
                . ' updated successfully.'
            );
        } else {
            $this->err(
                'Failed to update tag #'
                . $id . '.'
            );
            if (
                !empty(
                    $this->Tag->validationErrors
                )
            ) {
                foreach (
                    $this->Tag->validationErrors
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
     * Delete a tag with confirmation.
     *
     * @param int $id Tag ID.
     * @return void
     */
    private function __deleteTag($id)
    {
        $tag = $this->Tag->find('first', [
            'conditions' => ['Tag.id' => $id],
            'recursive' => -1,
        ]);
        if (empty($tag)) {
            $this->err(
                'Tag #' . $id . ' not found.'
            );
            return;
        }
        $name = $tag['Tag']['name'];
        if (mb_strlen($name) > 60) {
            $name = mb_substr($name, 0, 57)
                . '...';
        }
        if (
            !$this->__promptConfirm(
                'Delete tag #' . $id
                . " '" . $name . "'?"
                . ' This will remove it from all'
                . ' events/attributes.'
            )
        ) {
            $this->out('Cancelled.');
            return;
        }
        $result = $this->Tag->delete($id);
        if ($result) {
            $this->out(
                'Tag #' . $id
                . ' deleted successfully.'
            );
        } else {
            $this->err(
                'Failed to delete tag #'
                . $id . '.'
            );
        }
    }
}
