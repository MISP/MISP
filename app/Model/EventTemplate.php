<?php
App::uses('AppModel', 'Model');
App::uses('CakeText', 'Utility');
App::uses('ClassRegistry', 'Utility');
App::uses('JsonTool', 'Tools');

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
        foreach ($results as &$row) {
            if (isset($row[$this->alias]['definition']) && is_string($row[$this->alias]['definition'])) {
                $decoded = JsonTool::decode($row[$this->alias]['definition']);
                if (is_array($decoded)) {
                    $row[$this->alias]['definition'] = $decoded;
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
     * Semantic validation of an event-template definition.
     * Returns an array of human-readable error strings; empty array means valid.
     *
     * TODO(Phase 1.4): run JSON-schema structural validation first via
     * EventTemplateValidator. The checks below assume a valid structural shape
     * and are defensive against missing keys.
     */
    public function validateDefinition(array $definition)
    {
        $errors = array();

        if (!isset($definition['structure']) || !is_array($definition['structure'])) {
            $errors[] = '`structure` must be an array';
            return $errors;
        }

        $elementsById = array();
        $objectFieldIds = array();

        foreach ($definition['structure'] as $idx => $element) {
            if (!is_array($element) || !isset($element['type'])) {
                $errors[] = sprintf('structure[%d] is not a valid element', $idx);
                continue;
            }
            $type = $element['type'];
            $id = isset($element['id']) ? $element['id'] : null;

            if ($id === null || $id === '') {
                $errors[] = sprintf('structure[%d] (%s) is missing an id', $idx, $type);
                continue;
            }
            if (isset($elementsById[$id])) {
                $errors[] = sprintf('duplicate element id: %s', $id);
                continue;
            }
            $elementsById[$id] = $element;
            if ($type === 'object_field') {
                $objectFieldIds[$id] = true;
            }
        }

        foreach ($definition['structure'] as $element) {
            if (!is_array($element) || !isset($element['type'])) {
                continue;
            }
            $type = $element['type'];

            if ($type === 'object_reference') {
                foreach (array('from', 'to') as $endpoint) {
                    $ref = isset($element[$endpoint]) ? $element[$endpoint] : null;
                    if ($ref === null) {
                        $errors[] = sprintf('object_reference missing %s', $endpoint);
                        continue;
                    }
                    if (!isset($objectFieldIds[$ref])) {
                        $errors[] = sprintf(
                            'object_reference %s "%s" does not point to an object_field in this template',
                            $endpoint, $ref
                        );
                    }
                }
            } elseif ($type === 'attribute_field') {
                $misp = isset($element['misp']) && is_array($element['misp']) ? $element['misp'] : array();
                $category = isset($misp['category']) ? $misp['category'] : null;
                $attrType = isset($misp['type']) ? $misp['type'] : null;
                $id = isset($element['id']) ? $element['id'] : '?';
                if ($category === null || $attrType === null) {
                    $errors[] = sprintf('attribute_field "%s" missing category or type', $id);
                    continue;
                }
                if (!$this->isValidCategoryType($category, $attrType)) {
                    $errors[] = sprintf(
                        'attribute_field "%s": type "%s" is not valid in category "%s"',
                        $id, $attrType, $category
                    );
                }
            } elseif ($type === 'object_field') {
                $ot = isset($element['object_template']) && is_array($element['object_template'])
                    ? $element['object_template']
                    : array();
                $uuid = isset($ot['uuid']) ? $ot['uuid'] : null;
                $pinned = isset($ot['pinned_version']) ? (int)$ot['pinned_version'] : null;
                $id = isset($element['id']) ? $element['id'] : '?';
                if ($uuid === null || $pinned === null) {
                    $errors[] = sprintf('object_field "%s" missing object_template.uuid or pinned_version', $id);
                    continue;
                }
                if (!$this->objectTemplateAvailable($uuid, $pinned)) {
                    $errors[] = sprintf(
                        'object_field "%s": object template %s at version >= %d is not installed on this instance',
                        $id, $uuid, $pinned
                    );
                }
            }
        }

        return $errors;
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

    private function isValidCategoryType($category, $type)
    {
        $mispAttribute = ClassRegistry::init('MispAttribute');
        $catDefs = $mispAttribute->categoryDefinitions;
        if (!isset($catDefs[$category]['types'])) {
            return false;
        }
        return in_array($type, $catDefs[$category]['types'], true);
    }

    private function objectTemplateAvailable($uuid, $pinnedVersion)
    {
        $objectTemplate = ClassRegistry::init('ObjectTemplate');
        $row = $objectTemplate->find('first', array(
            'conditions' => array(
                'ObjectTemplate.uuid' => strtolower($uuid),
                'ObjectTemplate.active' => true,
            ),
            'fields' => array('ObjectTemplate.version'),
            'recursive' => -1,
        ));
        if (empty($row)) {
            return false;
        }
        return (int)$row['ObjectTemplate']['version'] >= (int)$pinnedVersion;
    }
}
