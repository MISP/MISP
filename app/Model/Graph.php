<?php
App::uses('AppModel', 'Model');
App::uses('AnalystData', 'Model');
App::uses('AnalystGraphDocumentTool', 'Tools');

/**
 * An analyst graph: analyst data attached to one record, whose content is a
 * document of the records it shows and their layout.
 */
class Graph extends AnalystData
{
    public $useTable = 'analyst_graphs';

    public $recursive = -1;

    public $actsAs = array(
        'AuditLog',
        'Containable',
        'AnalystData',
    );

    public $current_type = 'Graph';
    public $current_type_id = 3;

    const VALID_TARGETS = [
        'Collection',
        'Event',
        'GalaxyCluster',
    ];

    public const EDITABLE_FIELDS = [
        'name',
        'description',
    ];

    public const SEARCHABLE_FIELDS = [
        'name',
        'description',
    ];

    const ACTIVE_SETTING = 'intelligence_graph_active';

    /** What a list of graphs reads of each: everything but the document. */
    const SUMMARY_FIELDS = [
        'id', 'uuid', 'name', 'description', 'object_uuid', 'object_type',
        'distribution', 'sharing_group_id', 'org_uuid', 'orgc_uuid', 'locked',
        'created', 'modified', 'revision', 'node_count', 'forked_from_uuid',
    ];

    const EDITABLE_LIMIT = 200;

    public $childValidate = [
        'name' => [
            'notBlank' => [
                'rule' => 'notBlank',
                'message' => 'A graph needs a name.',
                'required' => 'create',
            ],
            'maxLength' => [
                'rule' => ['maxLength', 191],
                'message' => 'The name is at most 191 characters.',
            ],
        ],
        'object_type' => [
            'validTarget' => [
                'rule' => ['inList', self::VALID_TARGETS],
                'message' => 'A graph attaches to a collection, an event or a galaxy cluster.',
                'required' => 'create',
            ],
        ],
        'content' => [
            'validDocument' => [
                'rule' => 'validDocument',
            ],
        ],
    ];

    public function getEditableFields(): array
    {
        return array_values(array_diff(parent::getEditableFields(), ['language']));
    }

    /**
     * A graph only points at uuid-addressed records: its table has no
     * SHA-256 address column to withhold rows by.
     */
    public function beforeFind($query)
    {
        return $query;
    }

    public function beforeValidate($options = array())
    {
        parent::beforeValidate($options);
        if (empty($this->id) && empty($this->data[$this->alias]['id']) && !isset($this->data[$this->alias]['content'])) {
            $this->data[$this->alias]['content'] = AnalystGraphDocumentTool::emptyDocument();
        }
        return true;
    }

    /**
     * Validates the document and stores it in its normalised, encoded form.
     *
     * @param array $check
     * @return bool|string
     */
    public function validDocument(array $check)
    {
        list($document, $errors) = AnalystGraphDocumentTool::normalise($check['content']);
        if (!empty($errors)) {
            return implode(' ', array_slice($errors, 0, 10));
        }
        $this->data[$this->alias]['content'] = AnalystGraphDocumentTool::encode($document);
        return true;
    }

    /**
     * Content as a write by this user stores it (AnalystGraphData::documentForWrite).
     * A document that does not validate is returned as given, for validation
     * to report.
     *
     * @param array $user
     * @param array|string|null $content
     * @param array|null $stored The stored document, decoded; null on create
     * @return mixed
     */
    public function contentForWrite(array $user, $content, $stored = null)
    {
        list($document, $errors) = AnalystGraphDocumentTool::normalise($content);
        if (!empty($errors)) {
            return $content;
        }
        return ClassRegistry::init('AnalystGraphData')->documentForWrite($user, $document, $stored);
    }

    /**
     * The saved row as the after-save workflow receives it: workflow modules
     * can forward data out, so answers go as their keys.
     *
     * @param array $data
     * @return array
     */
    protected function workflowTriggerData(array $data)
    {
        if (isset($data['content'])) {
            $document = is_string($data['content']) ? json_decode($data['content'], true) : $data['content'];
            if (is_array($document)) {
                $data['content'] = AnalystGraphDocumentTool::encode(AnalystGraphDocumentTool::answersAsKeys($document));
            }
        }
        return $data;
    }

    public function beforeSave($options = [])
    {
        parent::beforeSave($options);
        $data = &$this->data[$this->alias];
        if (isset($data['content'])) {
            $data = AnalystGraphDocumentTool::measure($data['content']) + $data;
        }
        $id = $data['id'] ?? $this->id;
        if (empty($id)) {
            $data['revision'] = 1;
        } else {
            $stored = $this->find('first', [
                'conditions' => [$this->alias . '.id' => $id],
                'fields' => [$this->alias . '.revision'],
                'recursive' => -1,
                'callbacks' => false,
            ]);
            $data['revision'] = (int)($stored[$this->alias]['revision'] ?? 0) + 1;
        }
        // A save restricted to a field list still writes the derived columns
        if (!empty($this->whitelist)) {
            $this->whitelist = array_merge($this->whitelist, ['revision', 'content_size', 'node_count']);
        }
        return true;
    }

    /**
     * Replace a graph's document under a row lock. With $baseRevision, a graph
     * saved since that revision is left untouched and the result is a conflict.
     *
     * @param int $id
     * @param callable $change Given the stored document, returns the new one,
     *                         or null to leave it as it is
     * @param int|null $baseRevision
     * @return array status (saved, unchanged, conflict, invalid or missing),
     *               revision, errors; once saved also node_count,
     *               content_size, modified
     * @throws Exception
     */
    public function writeContent($id, callable $change, $baseRevision = null)
    {
        $db = $this->getDataSource();
        $db->begin();
        try {
            $rows = $db->fetchAll(
                sprintf(
                    'SELECT %s, %s FROM %s WHERE %s = ? FOR UPDATE',
                    $db->name('revision'),
                    $db->name('content'),
                    $db->fullTableName($this),
                    $db->name('id')
                ),
                [(int)$id],
                ['cache' => false]
            );
            if (empty($rows)) {
                $db->rollback();
                return ['status' => 'missing', 'revision' => null, 'errors' => []];
            }
            $stored = array_merge(...array_values($rows[0]));
            $revision = (int)$stored['revision'];
            if ($baseRevision !== null && (int)$baseRevision !== $revision) {
                $db->rollback();
                return ['status' => 'conflict', 'revision' => $revision, 'errors' => []];
            }
            $document = json_decode($stored['content'], true);
            $document = is_array($document) ? $document : AnalystGraphDocumentTool::emptyDocument();
            $content = $change($document);
            if ($content === null) {
                $db->commit();
                return [
                    'status' => 'unchanged',
                    'revision' => $revision,
                    'node_count' => count($document['nodes'] ?? []),
                    'errors' => [],
                ];
            }
            $this->create(false);
            $saved = $this->save(
                [$this->alias => [
                    'id' => (int)$id,
                    'content' => $content,
                    'modified' => date('Y-m-d H:i:s'),
                ]],
                ['fieldList' => ['content', 'modified']]
            );
            if (!$saved) {
                $db->rollback();
                return ['status' => 'invalid', 'revision' => $revision, 'errors' => $this->validationErrors];
            }
            $db->commit();
        } catch (Exception $e) {
            $db->rollback();
            throw $e;
        }
        $saved = $saved[$this->alias];
        return [
            'status' => 'saved',
            'revision' => (int)$saved['revision'],
            'node_count' => (int)$saved['node_count'],
            'content_size' => (int)$saved['content_size'],
            'modified' => $saved['modified'],
            'errors' => [],
        ];
    }

    /**
     * Every column but the document: what a push collects of each graph.
     *
     * @return array
     */
    public function metadataFields(): array
    {
        $fields = [];
        foreach (array_keys($this->schema()) as $column) {
            if ($column !== 'content') {
                $fields[] = $this->alias . '.' . $column;
            }
        }
        return $fields;
    }

    /**
     * Reads the document, and the modified time that goes with it, into a
     * graph collected without them.
     *
     * @param array $graph
     * @return array|null null when the graph is gone
     */
    public function attachContent(array $graph)
    {
        $stored = $this->find('first', [
            'conditions' => [$this->alias . '.id' => $graph[$this->alias]['id']],
            'fields' => [$this->alias . '.content', $this->alias . '.modified'],
            'recursive' => -1,
            'callbacks' => false,
        ]);
        if (empty($stored)) {
            return null;
        }
        $graph[$this->alias]['content'] = AnalystGraphDocumentTool::decode($stored[$this->alias]['content']);
        $graph[$this->alias]['modified'] = $stored[$this->alias]['modified'];
        return $graph;
    }

    /**
     * Editing also needs the analyst-data permission, so `_canEdit` tells a
     * client whether to offer saving or forking.
     */
    public function canEditAnalystData(array $user, array $analystData, $modelType): bool
    {
        if (!parent::canEditAnalystData($user, $analystData, $modelType)) {
            return false;
        }
        return !empty($user['Role']['perm_site_admin']) || !empty($user['Role']['perm_analyst_data']);
    }

    /**
     * Graphs as a list shows them: no document, newest first.
     *
     * @param array $user
     * @param array $conditions
     * @param array $options `limit`; `targets` (default true) labels each
     *                       target as the user sees it; `parents` (default
     *                       false) adds `forked_from`, see withParents()
     * @return array Graph rows, unwrapped, `node_count` the nodes the user
     *               may read
     */
    public function summaries(array $user, array $conditions, array $options = [])
    {
        $this->current_user = $user;
        $rows = $this->find('all', [
            'conditions' => ['AND' => [$conditions, $this->buildConditions($user)]],
            'fields' => array_map(function ($field) {
                return $this->alias . '.' . $field;
            }, self::SUMMARY_FIELDS),
            'contain' => ['Org', 'Orgc'],
            'order' => [$this->alias . '.modified' => 'DESC', $this->alias . '.id' => 'DESC'],
            'limit' => $options['limit'] ?? null,
        ]);
        $graphs = array_map([$this, 'typed'], Hash::extract($rows, '{n}.' . $this->alias));
        $graphs = $this->withVisibleCounts($user, $graphs);
        if ($options['targets'] ?? true) {
            $graphs = ClassRegistry::init('AnalystGraphData')->labelTargets($user, $graphs);
        }
        if ($options['parents'] ?? false) {
            $graphs = $this->withParents($user, $graphs);
        }
        return $graphs;
    }

    /**
     * A fork's original, `forked_from` {uuid, name}, when the user may read
     * it; null when they may not, or it is gone.
     *
     * @param array $user
     * @param array $graphs Unwrapped
     * @return array
     */
    public function withParents(array $user, array $graphs)
    {
        $uuids = array_values(array_unique(array_filter(array_column($graphs, 'forked_from_uuid'))));
        $names = [];
        if (!empty($uuids)) {
            $names = $this->find('list', [
                'conditions' => ['AND' => [[$this->alias . '.uuid' => $uuids], $this->buildConditions($user)]],
                'fields' => [$this->alias . '.uuid', $this->alias . '.name'],
                'recursive' => -1,
                'callbacks' => false,
            ]);
        }
        foreach ($graphs as &$graph) {
            $parent = $graph['forked_from_uuid'] ?? null;
            $graph['forked_from'] = $parent !== null && isset($names[$parent])
                ? ['uuid' => $parent, 'name' => $names[$parent]]
                : null;
        }
        unset($graph);
        return $graphs;
    }

    /**
     * The stored count includes nodes the user may not read (G6).
     *
     * @param array $user
     * @param array $graphs Unwrapped, with `id`
     * @return array
     */
    public function withVisibleCounts(array $user, array $graphs)
    {
        if (empty($graphs)) {
            return $graphs;
        }
        $counts = ClassRegistry::init('AnalystGraphData')->visibleCounts(
            $user,
            $this->storedContents(array_column($graphs, 'id'))
        );
        foreach ($graphs as &$graph) {
            $graph['node_count'] = $counts[$graph['id']] ?? 0;
        }
        unset($graph);
        return $graphs;
    }

    /**
     * @param array $ids
     * @return array id => stored document, encoded
     */
    public function storedContents(array $ids)
    {
        return $this->find('list', [
            'conditions' => [$this->alias . '.id' => $ids],
            'fields' => [$this->alias . '.id', $this->alias . '.content'],
            'recursive' => -1,
            'callbacks' => false,
        ]);
    }

    /**
     * A graph row with its numbers and flags as JSON types, as the graph
     * host does arithmetic on `revision`.
     *
     * @param array $graph Unwrapped
     * @return array
     */
    public function typed(array $graph)
    {
        foreach (['id', 'distribution', 'revision', 'node_count', 'content_size'] as $field) {
            if (isset($graph[$field])) {
                $graph[$field] = (int)$graph[$field];
            }
        }
        if (array_key_exists('sharing_group_id', $graph)) {
            $graph['sharing_group_id'] = $graph['sharing_group_id'] === null ? null : (int)$graph['sharing_group_id'];
        }
        if (isset($graph['locked'])) {
            $graph['locked'] = (bool)$graph['locked'];
        }
        return $graph;
    }

    /**
     * The graphs the user may edit that their organisation created.
     *
     * @param array $user
     * @param bool $mine Only those naming the user's e-mail among their authors
     * @return array
     */
    public function editableBy(array $user, $mine = false)
    {
        if (empty($user['Role']['perm_site_admin']) && empty($user['Role']['perm_analyst_data'])) {
            return [];
        }
        $conditions = [$this->alias . '.orgc_uuid' => $user['Organisation']['uuid']];
        $email = strtolower(trim($user['email'] ?? ''));
        if ($mine) {
            if ($email === '') {
                return [];
            }
            $conditions[$this->alias . '.authors LIKE'] = '%' . addcslashes($email, '%_\\') . '%';
        }
        $graphs = $this->summaries($user, $conditions, ['limit' => self::EDITABLE_LIMIT]);
        $graphs = array_filter($graphs, function ($graph) {
            return !empty($graph['_canEdit']);
        });
        if ($mine && !empty($graphs)) {
            $authors = $this->find('list', [
                'conditions' => [$this->alias . '.id' => array_column($graphs, 'id')],
                'fields' => [$this->alias . '.id', $this->alias . '.authors'],
                'recursive' => -1,
                'callbacks' => false,
            ]);
            $graphs = array_filter($graphs, function ($graph) use ($authors, $email) {
                $names = preg_split('/[\s,;]+/', strtolower($authors[$graph['id']] ?? ''), -1, PREG_SPLIT_NO_EMPTY);
                return in_array($email, $names, true);
            });
        }
        return array_values($graphs);
    }

    /**
     * The graph "Add to graph" feeds: the one the user chose, while it is
     * still one they may edit.
     *
     * @param array $user
     * @param bool $targets Label its target
     * @return array|null
     */
    public function activeFor(array $user, $targets = true)
    {
        $stored = ClassRegistry::init('UserSetting')->getValueForUser($user['id'], self::ACTIVE_SETTING);
        $uuid = is_array($stored) ? ($stored['graph_uuid'] ?? null) : null;
        if (!is_string($uuid) || !Validation::uuid($uuid)) {
            return null;
        }
        $graphs = $this->summaries($user, [$this->alias . '.uuid' => strtolower($uuid)], ['targets' => $targets]);
        return !empty($graphs[0]['_canEdit']) ? $graphs[0] : null;
    }

    /**
     * Remember the graph "Add to graph" feeds, or forget it with null. The
     * legacy log is suppressed: its full-change entry would record the choice.
     *
     * @param array $user
     * @param string|null $uuid A graph the user may edit
     * @return bool
     */
    public function storeActive(array $user, $uuid)
    {
        $UserSetting = ClassRegistry::init('UserSetting');
        $logged = $UserSetting->Behaviors->enabled('SysLogLogable.SysLogLogable');
        $UserSetting->Behaviors->disable('SysLogLogable.SysLogLogable');
        try {
            return (bool)$UserSetting->setSettingInternal($user['id'], self::ACTIVE_SETTING, ['graph_uuid' => $uuid]);
        } finally {
            if ($logged) {
                $UserSetting->Behaviors->enable('SysLogLogable.SysLogLogable');
            }
        }
    }

    /**
     * Read by AuditLogBehavior: the document is logged as a summary.
     *
     * @param string $field
     * @param mixed $old
     * @param mixed $new
     * @return array|null
     */
    public function auditLogSummary($field, $old, $new)
    {
        if ($field !== 'content') {
            return null;
        }
        $summary = AnalystGraphDocumentTool::summariseChange($old, $new);
        if (isset($this->data[$this->alias]['revision'])) {
            $summary = ['revision' => (int)$this->data[$this->alias]['revision']] + $summary;
        }
        return $summary;
    }
}
