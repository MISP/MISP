<?php
App::uses('AppModel', 'Model');
App::uses('CakeText', 'Utility');
App::uses('JsonTool', 'Tools');
App::uses('Folder', 'Utility');
App::uses('File', 'Utility');
App::uses('EventTemplateValidator', 'Tools');

/**
 * EventTemplate — v2 event templating system.
 *
 * Storage model is a thin relational envelope around a JSON `definition`
 * document. See docs/dev/event-templating-prd.md §6.2 and §7 for the shape.
 *
 * This model:
 *   - lazy-decodes the JSON blob on read (afterFind),
 *   - encodes on save (beforeSave) after running semantic validation,
 *   - generates the uuid and bumps `version` on every update (beforeValidate),
 *   - regenerates the `event_template_object_dependencies` sidecar after save,
 *   - wraps the whole save in a transaction so parent row + dependency rebuild
 *     either both commit or both roll back.
 *
 * Structural validation of the JSON (types, required fields, non-empty label,
 * info_template grammar) is deferred to the EventTemplateValidator lib added
 * in Phase 1.4 via league/json-schema. The semantic checks below assume a
 * valid structural shape and are defensive against missing keys.
 */
class EventTemplate extends AppModel
{
    public $actsAs = array('AuditLog', 'Containable');

    public $displayField = 'name';

    public $belongsTo = array(
        'Organisation' => array(
            'className' => 'Organisation',
            'foreignKey' => 'org_id',
        ),
        'CreatorUser' => array(
            'className' => 'User',
            'foreignKey' => 'creator_user_id',
        ),
    );

    public $hasMany = array(
        'EventTemplateObjectDependency' => array(
            'className' => 'EventTemplateObjectDependency',
            'foreignKey' => 'event_template_id',
            'dependent' => true,
        ),
    );

    public $validate = array(
        'uuid' => array(
            'notBlank' => array(
                'rule' => 'notBlank',
                'message' => 'uuid is required',
            ),
            'uuid' => array(
                'rule' => 'uuid',
                'message' => 'uuid must be a valid UUID',
            ),
            'unique' => array(
                'rule' => 'isUnique',
                'message' => 'uuid must be unique',
                'on' => 'create',
            ),
        ),
        'name' => array(
            'notBlank' => array(
                'rule' => 'notBlank',
                'message' => 'name is required',
            ),
            'maxLength' => array(
                'rule' => array('maxLength', 255),
                'message' => 'name must be 255 characters or fewer',
            ),
        ),
        'org_id' => array(
            'rule' => 'naturalNumber',
            'message' => 'org_id is required and must be a natural number',
        ),
        'creator_user_id' => array(
            'rule' => 'naturalNumber',
            'message' => 'creator_user_id is required and must be a natural number',
        ),
        'distribution' => array(
            'rule' => array('inList', array('0', '1', 0, 1)),
            'message' => 'distribution must be 0 (org only) or 1 (community)',
        ),
        'active' => array(
            'rule' => 'boolean',
            'message' => 'active must be 0 or 1',
        ),
        'version' => array(
            'rule' => 'naturalNumber',
            'message' => 'version must be a positive integer',
        ),
        'definition' => array(
            'rule' => 'notBlank',
            'message' => 'definition is required',
        ),
    );

    public function beforeValidate($options = array())
    {
        $alias = $this->alias;
        if (!isset($this->data[$alias])) {
            return true;
        }
        $row = &$this->data[$alias];

        if (empty($row['uuid'])) {
            $row['uuid'] = CakeText::uuid();
        } else {
            $row['uuid'] = strtolower($row['uuid']);
        }

        $now = date('Y-m-d H:i:s');
        if (empty($this->id)) {
            if (empty($row['created'])) {
                $row['created'] = $now;
            }
            if (empty($row['version'])) {
                $row['version'] = 1;
            }
        } else {
            if (!isset($row['version'])) {
                $existing = $this->find('first', array(
                    'conditions' => array($alias . '.id' => $this->id),
                    'recursive' => -1,
                    'fields' => array($alias . '.version'),
                ));
                $current = isset($existing[$alias]['version']) ? (int)$existing[$alias]['version'] : 1;
                $row['version'] = $current + 1;
            } else {
                $row['version'] = (int)$row['version'] + 1;
            }
        }
        $row['modified'] = $now;

        // Definition handling happens before CakePHP's $validate rules fire.
        // If the caller passed an array we run semantic validation and encode
        // to JSON so `notBlank` (and any downstream rule) sees a string.
        // Pre-encoded strings pass through unchanged.
        if (isset($row['definition']) && is_array($row['definition'])) {
            $errors = $this->validateDefinition($row['definition']);
            if (!empty($errors)) {
                foreach ($errors as $err) {
                    $this->validationErrors['definition'][] = $err;
                }
                return false;
            }
            $row['definition'] = JsonTool::encode($row['definition']);
        }

        return true;
    }

    public function afterSave($created, $options = array())
    {
        $alias = $this->alias;
        if (!isset($this->data[$alias]) || empty($this->id)) {
            return true;
        }

        $row = $this->data[$alias];
        $definition = null;
        if (isset($row['definition'])) {
            if (is_array($row['definition'])) {
                $definition = $row['definition'];
            } elseif (is_string($row['definition'])) {
                $decoded = JsonTool::decode($row['definition']);
                if (is_array($decoded)) {
                    $definition = $decoded;
                }
            }
        }

        if ($definition === null) {
            return true;
        }

        $this->EventTemplateObjectDependency->deleteAll(
            array('EventTemplateObjectDependency.event_template_id' => $this->id),
            false
        );

        $deps = $this->extractObjectDependencies($definition);
        foreach ($deps as $dep) {
            $dep['event_template_id'] = $this->id;
            $this->EventTemplateObjectDependency->create();
            if (!$this->EventTemplateObjectDependency->save($dep)) {
                throw new RuntimeException(
                    'Failed to write event-template object-dependency row: '
                    . JsonTool::encode($this->EventTemplateObjectDependency->validationErrors)
                );
            }
        }

        return true;
    }

    public function afterFind($results, $primary = false)
    {
        if (!is_array($results)) {
            return $results;
        }
        // Collect ids for which we need a backfill of `default` — see
        // below for why a backfill is needed at all.
        $needBackfill = array();
        foreach ($results as &$row) {
            if (isset($row[$this->alias]['definition']) && is_string($row[$this->alias]['definition'])) {
                $decoded = JsonTool::decode($row[$this->alias]['definition']);
                if (is_array($decoded)) {
                    $row[$this->alias]['definition'] = $decoded;
                }
            }
            // `default` is a MySQL reserved word. Cake's DboSource enumerates
            // columns from $Model->schema() and quotes them, so the SELECT
            // does include `default`, but the result-row mapping drops the
            // column from the returned associative array on the live setup
            // (verified via the integration test). Writes work fine —
            // this is read-side only. Backfill from a tight side query.
            if (isset($row[$this->alias]) && is_array($row[$this->alias])
                && !array_key_exists('default', $row[$this->alias])
                && isset($row[$this->alias]['id'])
            ) {
                $needBackfill[(int)$row[$this->alias]['id']] = true;
            }
        }
        unset($row);
        if (!empty($needBackfill)) {
            $ids = array_keys($needBackfill);
            $db = $this->getDataSource();
            $rows = $db->rawQuery(sprintf(
                'SELECT id, `default` FROM `event_templates` WHERE id IN (%s)',
                implode(',', array_map('intval', $ids))
            ));
            $byId = array();
            if ($rows) {
                foreach ($rows->fetchAll(PDO::FETCH_ASSOC) as $r) {
                    $byId[(int)$r['id']] = (int)$r['default'];
                }
            }
            foreach ($results as &$row) {
                if (isset($row[$this->alias]['id'])) {
                    $rid = (int)$row[$this->alias]['id'];
                    if (isset($byId[$rid])) {
                        $row[$this->alias]['default'] = $byId[$rid];
                    }
                }
            }
        }
        return $results;
    }

    /**
     * Wraps the save in a transaction so the parent row and the dependency
     * sidecar rebuild (in afterSave) either both commit or both roll back.
     */
    public function save($data = null, $validate = true, $fieldList = array())
    {
        $dataSource = $this->getDataSource();
        $transactionBegun = $dataSource->begin();

        try {
            $result = parent::save($data, $validate, $fieldList);
            if (!$result) {
                if ($transactionBegun) {
                    $dataSource->rollback();
                }
                return false;
            }
            if ($transactionBegun) {
                $dataSource->commit();
            }
            return $result;
        } catch (Exception $e) {
            if ($transactionBegun) {
                $dataSource->rollback();
            }
            throw $e;
        }
    }

    /**
     * Delegate to EventTemplateValidator (Phase 1.4), which runs structural
     * validation (against app/files/schemas/event-template-v1.schema.json)
     * and semantic validation (cross-element + DB-backed checks). Returns an
     * array of human-readable error strings; empty array means valid.
     */
    public function validateDefinition(array $definition)
    {
        App::uses('EventTemplateValidator', 'Tools');
        $validator = new EventTemplateValidator();
        return $validator->validate($definition);
    }

    /**
     * Walks the definition's structure and returns a deduplicated array of
     * {object_template_uuid, object_template_name, pinned_version} rows, one
     * per distinct object template referenced by the template.
     */
    public function extractObjectDependencies(array $definition)
    {
        if (!isset($definition['structure']) || !is_array($definition['structure'])) {
            return array();
        }

        $seen = array();
        $rows = array();
        foreach ($definition['structure'] as $element) {
            if (!is_array($element) || !isset($element['type']) || $element['type'] !== 'object_field') {
                continue;
            }
            $ot = isset($element['object_template']) && is_array($element['object_template'])
                ? $element['object_template']
                : array();
            $uuid = isset($ot['uuid']) ? strtolower((string)$ot['uuid']) : null;
            $name = isset($ot['name']) ? (string)$ot['name'] : null;
            $pinned = isset($ot['pinned_version']) ? (int)$ot['pinned_version'] : null;
            if ($uuid === null || $name === null || $pinned === null) {
                continue;
            }
            if (isset($seen[$uuid])) {
                if ($pinned > $rows[$seen[$uuid]]['pinned_version']) {
                    $rows[$seen[$uuid]]['pinned_version'] = $pinned;
                }
                continue;
            }
            $seen[$uuid] = count($rows);
            $rows[] = array(
                'object_template_uuid' => $uuid,
                'object_template_name' => $name,
                'pinned_version' => $pinned,
            );
        }
        return $rows;
    }

    /**
     * Path to the bundled library submodule. The library is checked in
     * via .gitmodules and shipped alongside other content submodules
     * (misp-objects, misp-galaxy, etc.). Each `templates/<slug>/definition.json`
     * is a self-contained event-template definition; see the library's
     * README + schema_event_template.json for the shape.
     */
    const LIBRARY_DIR = APP . 'files' . DS . 'misp-event-templates' . DS . 'templates';

    /**
     * Walk the bundled misp-event-templates submodule and reconcile its
     * contents with this instance's `event_templates` table. Each on-disk
     * `definition.json` is parsed, validated against the v1 schema +
     * semantic checks, and routed to one of four outcomes per PRD §5.3:
     *
     *   - install        — uuid not present locally → insert with
     *                      default = 1, active = 0, distribution = 1.
     *   - updated        — present locally with default = 1 AND content
     *                      differs from the library version → overwrite,
     *                      preserving id and ownership.
     *   - skipped_current — present locally with default = 1 but content
     *                      already matches the library version → no-op.
     *   - skipped_forked — present locally with default = 0 → operator
     *                      has explicitly forked this row; library
     *                      updates leave it alone (PRD §5.3 / §15.3).
     *
     * Failures (parse errors, schema validation, save failures) land
     * under `failed` with a message and the offending file path.
     *
     * Site-admin gating is the controller's responsibility — this model
     * method is permission-agnostic. The importing user is recorded as
     * the row's creator_user_id / org_id on every install.
     *
     * @param array $user CakePHP Auth user shape (id, org_id, …)
     * @return array {
     *     installed: array<int, array{slug,uuid,name,id}>,
     *     updated: array<int, array{slug,uuid,name,id}>,
     *     skipped_current: array<int, array{slug,uuid,name,id}>,
     *     skipped_forked: array<int, array{slug,uuid,name,id}>,
     *     failed: array<int, array{slug,error}>,
     *   }
     */
    public function updateFromLibrary(array $user)
    {
        $summary = array(
            'installed' => array(),
            'updated' => array(),
            'skipped_current' => array(),
            'skipped_forked' => array(),
            'failed' => array(),
        );

        if (!is_dir(self::LIBRARY_DIR)) {
            $summary['failed'][] = array(
                'slug' => null,
                'error' => sprintf(
                    'Library path %s does not exist. Run `git submodule update --init app/files/misp-event-templates`.',
                    self::LIBRARY_DIR
                ),
            );
            return $summary;
        }

        $folder = new Folder(self::LIBRARY_DIR);
        list($subdirs,) = $folder->read(true, false, true);
        if (empty($subdirs)) {
            return $summary;
        }

        $validator = new EventTemplateValidator();

        foreach ($subdirs as $dir) {
            $slug = basename($dir);
            $path = $dir . DS . 'definition.json';
            if (!file_exists($path)) {
                $summary['failed'][] = array(
                    'slug' => $slug,
                    'error' => 'definition.json missing in template directory',
                );
                continue;
            }

            $raw = @file_get_contents($path);
            if ($raw === false) {
                $summary['failed'][] = array(
                    'slug' => $slug,
                    'error' => 'cannot read definition.json',
                );
                continue;
            }

            $definition = json_decode($raw, true);
            if (!is_array($definition)) {
                $summary['failed'][] = array(
                    'slug' => $slug,
                    'error' => 'definition.json is not valid JSON',
                );
                continue;
            }

            $errs = $validator->validate($definition);
            if (!empty($errs)) {
                $summary['failed'][] = array(
                    'slug' => $slug,
                    'error' => 'schema/semantic validation failed: ' . implode('; ', $errs),
                );
                continue;
            }

            $libraryUuid = isset($definition['uuid']) ? strtolower((string)$definition['uuid']) : '';
            if ($libraryUuid === '') {
                $summary['failed'][] = array(
                    'slug' => $slug,
                    'error' => 'definition.json has no uuid',
                );
                continue;
            }

            // Explicit field list because `default` is a MySQL reserved
            // word — Cake's `SELECT *` short-circuit drops the column
            // from the returned associative array on some setups even
            // though writes work fine. Listing the columns by name
            // forces them through.
            $existing = $this->find('first', array(
                'recursive' => -1,
                'conditions' => array('EventTemplate.uuid' => $libraryUuid),
                'fields' => array(
                    'EventTemplate.id',
                    'EventTemplate.uuid',
                    'EventTemplate.name',
                    'EventTemplate.description',
                    'EventTemplate.org_id',
                    'EventTemplate.creator_user_id',
                    'EventTemplate.distribution',
                    'EventTemplate.active',
                    'EventTemplate.default',
                    'EventTemplate.version',
                    'EventTemplate.definition',
                ),
            ));

            $libraryName = isset($definition['name']) ? (string)$definition['name'] : '';

            if (empty($existing)) {
                // INSTALL — fresh row, library-managed, inactive by default.
                $row = array(
                    'uuid' => $libraryUuid,
                    'name' => $libraryName,
                    'description' => isset($definition['description']) ? $definition['description'] : null,
                    'org_id' => isset($user['org_id']) ? (int)$user['org_id'] : 0,
                    'creator_user_id' => isset($user['id']) ? (int)$user['id'] : 0,
                    'distribution' => 1,
                    'active' => 0,
                    'default' => 1,
                    'definition' => $definition,
                );
                $this->create();
                $ok = $this->save(array('EventTemplate' => $row));
                if (!$ok) {
                    $summary['failed'][] = array(
                        'slug' => $slug,
                        'error' => 'install save failed: '
                            . $this->__flattenValidationErrors($this->validationErrors),
                    );
                    continue;
                }
                $summary['installed'][] = array(
                    'slug' => $slug,
                    'uuid' => $libraryUuid,
                    'name' => $libraryName,
                    'id' => (int)$this->id,
                );
                continue;
            }

            // Existing row.
            if ((int)$existing['EventTemplate']['default'] !== 1) {
                // SKIPPED_FORKED — operator has flipped default to 0.
                $summary['skipped_forked'][] = array(
                    'slug' => $slug,
                    'uuid' => $libraryUuid,
                    'name' => $libraryName,
                    'id' => (int)$existing['EventTemplate']['id'],
                );
                continue;
            }

            // default = 1 → eligible for update. Compare content to skip
            // no-op overwrites. Comparison is on the schema-relevant
            // bits of the definition only — name and description are
            // also part of the contract.
            $existingDefinition = $existing['EventTemplate']['definition'];
            if (is_string($existingDefinition)) {
                $existingDefinition = json_decode($existingDefinition, true);
            }
            $sameDefinition = $this->__definitionsEqual(
                is_array($existingDefinition) ? $existingDefinition : array(),
                $definition
            );
            $sameMeta = (
                ((string)$existing['EventTemplate']['name']) === $libraryName
                && (string)($existing['EventTemplate']['description'] ?? '')
                    === (string)($definition['description'] ?? '')
            );
            if ($sameDefinition && $sameMeta) {
                $summary['skipped_current'][] = array(
                    'slug' => $slug,
                    'uuid' => $libraryUuid,
                    'name' => $libraryName,
                    'id' => (int)$existing['EventTemplate']['id'],
                );
                continue;
            }

            // UPDATED — overwrite preserving id, ownership, active flag.
            $row = array(
                'id' => (int)$existing['EventTemplate']['id'],
                'uuid' => $libraryUuid,
                'name' => $libraryName,
                'description' => isset($definition['description']) ? $definition['description'] : null,
                'distribution' => isset($existing['EventTemplate']['distribution'])
                    ? (int)$existing['EventTemplate']['distribution']
                    : 1,
                'active' => isset($existing['EventTemplate']['active'])
                    ? (int)$existing['EventTemplate']['active']
                    : 0,
                'default' => 1,
                'definition' => $definition,
            );
            $this->id = (int)$existing['EventTemplate']['id'];
            $ok = $this->save(array('EventTemplate' => $row));
            if (!$ok) {
                $summary['failed'][] = array(
                    'slug' => $slug,
                    'error' => 'update save failed: '
                        . $this->__flattenValidationErrors($this->validationErrors),
                );
                continue;
            }
            $summary['updated'][] = array(
                'slug' => $slug,
                'uuid' => $libraryUuid,
                'name' => $libraryName,
                'id' => (int)$existing['EventTemplate']['id'],
            );
        }

        return $summary;
    }

    /**
     * Deep-equal two decoded template definitions. Used by
     * updateFromLibrary to skip no-op overwrites in the summary.
     * Order-sensitive on arrays (which is correct for `structure[]`)
     * and order-insensitive on object keys via canonical JSON encode.
     */
    private function __definitionsEqual(array $a, array $b)
    {
        $canon = function ($v) use (&$canon) {
            if (is_array($v)) {
                if (array_keys($v) === range(0, count($v) - 1)) {
                    return array_map($canon, $v);
                }
                ksort($v);
                $out = array();
                foreach ($v as $k => $vv) {
                    $out[$k] = $canon($vv);
                }
                return $out;
            }
            return $v;
        };
        return json_encode($canon($a)) === json_encode($canon($b));
    }

    /**
     * Auto-populate the event_templates table from the bundled
     * misp-event-templates submodule when it's currently empty.
     * Mirrors ObjectTemplate::populateIfEmpty() — same pattern,
     * same name. Site-admin gating is the controller's responsibility.
     *
     * Returns the loader's summary if a populate ran, or null if
     * the table was non-empty (no work done).
     *
     * @param array $user CakePHP Auth user (id + org_id)
     * @return array|null
     */
    public function populateIfEmpty(array $user)
    {
        if ($this->hasAny()) {
            return null;
        }
        return $this->updateFromLibrary($user);
    }

    private function __flattenValidationErrors($validationErrors)
    {
        if (!is_array($validationErrors) || empty($validationErrors)) {
            return '(no detail)';
        }
        $out = array();
        foreach ($validationErrors as $field => $msgs) {
            if (is_array($msgs)) {
                foreach ($msgs as $m) {
                    $out[] = sprintf('%s: %s', $field, (string)$m);
                }
            } else {
                $out[] = sprintf('%s: %s', $field, (string)$msgs);
            }
        }
        return implode('; ', $out);
    }

}
