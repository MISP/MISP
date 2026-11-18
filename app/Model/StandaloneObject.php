<?php
App::uses('AppModel', 'Model');
App::uses('AnalystGraphDocumentTool', 'Tools');

/**
 * An object MISP does not hold as a record of an event, kept by the
 * collections that hold it: a module's answer, or one made from a template.
 * Its attribute values stay inside it, so they have no value page and no
 * correlation. It is never edited: one taken from an answer is named by its
 * content, so the same answer is one record everywhere; one made by hand
 * gets a random uuid.
 */
class StandaloneObject extends AppModel
{
    public $recursive = -1;

    const NAME_LENGTH = 255;

    public $validate = [
        'uuid' => [
            'uuid' => [
                'rule' => 'uuid',
                'message' => 'Please provide a valid RFC 4122 UUID',
            ],
            'unique' => [
                'rule' => 'isUnique',
                'message' => 'The uuid provided is not unique',
            ],
        ],
        'name' => [
            'rule' => ['maxLength', self::NAME_LENGTH],
            'message' => 'An object name holds at most 255 characters.',
        ],
    ];

    public function afterFind($results, $primary = false)
    {
        foreach ($results as $k => $result) {
            if (isset($result[$this->alias]['attributes']) && is_string($result[$this->alias]['attributes'])) {
                $results[$k][$this->alias]['attributes'] = json_decode($result[$this->alias]['attributes'], true) ?: [];
            }
        }
        return $results;
    }

    /**
     * A module's answer of kind object as a record: the uuid derived from
     * the module and the content, the template looked up by the name.
     *
     * @param mixed $module
     * @param mixed $content
     * @param string[] $errors
     * @return array|null The record, not saved
     */
    public function fromAnswer($module, $content, array &$errors)
    {
        if (!is_string($module) || !preg_match(AnalystGraphDocumentTool::MODULE_PATTERN, $module)) {
            $errors[] = __('an object from a module names the module.');
            return null;
        }
        $content = AnalystGraphDocumentTool::normaliseObjectContent($content, $errors);
        if ($content === null || !self::fits($content, $errors)) {
            return null;
        }
        $template = $this->templateNamed($content['name']);
        return self::record(AnalystGraphDocumentTool::answerUuid($content, $module), $module, $content, $template);
    }

    /**
     * An object made from a template: each attribute names its relation,
     * which gives its type; the template's requirements are checked.
     *
     * @param mixed $templateRef The template's uuid (its newest version) or id
     * @param mixed $attributes [{relation, value, comment?, to_ids?, category?}]
     * @param mixed $comment
     * @param string[] $errors
     * @return array|null The record, not saved
     */
    public function fromTemplate($templateRef, $attributes, $comment, array &$errors)
    {
        $template = $this->template($templateRef);
        if ($template === null) {
            $errors[] = __('No such object template.');
            return null;
        }
        if (!is_array($attributes) || empty($attributes) || array_keys($attributes) !== range(0, count($attributes) - 1)) {
            $errors[] = __('An object needs a list of attributes.');
            return null;
        }
        $elements = [];
        foreach ($template['ObjectTemplateElement'] as $element) {
            $elements[$element['object_relation']] = $element;
        }
        $types = ClassRegistry::init('MispAttribute')->typeDefinitions;
        $built = [];
        foreach ($attributes as $i => $attribute) {
            $relation = is_array($attribute) ? ($attribute['relation'] ?? $attribute['object_relation'] ?? null) : null;
            if (!is_string($relation) || !isset($elements[$relation])) {
                $errors[] = __('attributes[%s]: not a relation of the template “%s”.', $i, $template['ObjectTemplate']['name']);
                return null;
            }
            $value = $attribute['value'] ?? null;
            if (!is_scalar($value) || trim((string)$value) === '') {
                $errors[] = __('attributes[%s]: %s needs a value.', $i, $relation);
                return null;
            }
            $type = $elements[$relation]['type'];
            $categories = (array)($elements[$relation]['categories'] ?? []);
            $category = is_string($attribute['category'] ?? null) && in_array($attribute['category'], $categories, true)
                ? $attribute['category']
                : ($categories[0] ?? ($types[$type]['default_category'] ?? ''));
            $built[] = [
                'relation' => $relation,
                'type' => $type,
                'value' => trim((string)$value),
                'category' => (string)$category,
                'comment' => is_string($attribute['comment'] ?? null) ? $attribute['comment'] : '',
                'to_ids' => array_key_exists('to_ids', $attribute) ? !empty($attribute['to_ids']) : !empty($types[$type]['to_ids']),
            ];
        }
        $conformity = ClassRegistry::init('ObjectTemplate')->checkTemplateConformity($template, [
            'Attribute' => array_map(function ($attribute) {
                return ['object_relation' => $attribute['relation']];
            }, $built),
        ]);
        if ($conformity !== true) {
            $errors[] = $conformity;
            return null;
        }
        $content = AnalystGraphDocumentTool::normaliseObjectContent([
            'name' => $template['ObjectTemplate']['name'],
            'meta_category' => (string)($template['ObjectTemplate']['meta-category'] ?? ''),
            'description' => (string)($template['ObjectTemplate']['description'] ?? ''),
            'comment' => is_string($comment) ? $comment : '',
            'attributes' => $built,
        ], $errors);
        if ($content === null || !self::fits($content, $errors)) {
            return null;
        }
        return self::record(CakeText::uuid(), null, $content, [
            'uuid' => $template['ObjectTemplate']['uuid'],
            'version' => (int)$template['ObjectTemplate']['version'],
        ]);
    }

    /**
     * A record as another instance sends it. One from a module must carry
     * the uuid its content derives; one made by hand any uuid.
     *
     * @param mixed $record
     * @param string[] $errors
     * @return array|null
     */
    public function fromRemote($record, array &$errors)
    {
        if (!is_array($record) || !is_string($record['uuid'] ?? null) || !Validation::uuid($record['uuid'])) {
            $errors[] = __('A standalone object needs a uuid.');
            return null;
        }
        $content = AnalystGraphDocumentTool::normaliseObjectContent([
            'name' => $record['name'] ?? null,
            'meta_category' => $record['meta_category'] ?? '',
            'description' => $record['description'] ?? '',
            'comment' => $record['comment'] ?? '',
            'attributes' => $record['attributes'] ?? [],
        ], $errors);
        if ($content === null || !self::fits($content, $errors)) {
            return null;
        }
        $module = $record['module'] ?? null;
        $uuid = strtolower($record['uuid']);
        if ($module !== null) {
            if (!is_string($module) || !preg_match(AnalystGraphDocumentTool::MODULE_PATTERN, $module)) {
                $errors[] = __('an object from a module names the module.');
                return null;
            }
            if (AnalystGraphDocumentTool::answerUuid($content, $module) !== $uuid) {
                $errors[] = __('The uuid of an object from a module is derived from its content.');
                return null;
            }
        }
        $template = null;
        if (is_string($record['template_uuid'] ?? null) && Validation::uuid($record['template_uuid'])) {
            $template = ['uuid' => strtolower($record['template_uuid']), 'version' => isset($record['template_version']) ? (int)$record['template_version'] : null];
        }
        return self::record($uuid, $module, $content, $template);
    }

    /**
     * Store a record unless one with its uuid exists: a stored record is
     * kept as it is.
     *
     * @param array $record As fromAnswer(), fromTemplate() or fromRemote() build it
     * @return bool
     */
    public function ensure(array $record)
    {
        if ($this->hasAny(['StandaloneObject.uuid' => $record['uuid']])) {
            return true;
        }
        $row = $record;
        $row['attributes'] = json_encode($record['attributes'], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        $row['created'] = date('Y-m-d H:i:s');
        $this->create();
        try {
            return (bool)$this->save(['StandaloneObject' => $row]);
        } catch (PDOException $e) {
            if (isset($e->errorInfo[0]) && strpos((string)$e->errorInfo[0], '23') === 0) {
                return true;
            }
            throw $e;
        }
    }

    /**
     * @param array $uuids
     * @return array lowercase uuid => the record, as the API shows it
     */
    public function records(array $uuids)
    {
        $uuids = array_values(array_unique(array_map('strtolower', array_filter($uuids, 'is_string'))));
        if (empty($uuids)) {
            return [];
        }
        $out = [];
        foreach (array_chunk($uuids, 500) as $chunk) {
            foreach ($this->find('all', ['conditions' => ['StandaloneObject.uuid' => $chunk]]) as $row) {
                $out[strtolower($row['StandaloneObject']['uuid'])] = self::shape($row['StandaloneObject']);
            }
        }
        return $out;
    }

    /**
     * Delete the record once no collection holds it.
     *
     * @param string $uuid
     * @return void
     */
    public function deleteIfUnheld($uuid)
    {
        $uuid = strtolower((string)$uuid);
        $held = ClassRegistry::init('CollectionElement')->hasAny([
            'CollectionElement.element_type' => 'StandaloneObject',
            'CollectionElement.element_uuid' => [$uuid, strtoupper($uuid)],
        ]);
        if (!$held) {
            $this->deleteAll(['StandaloneObject.uuid' => $uuid], false, false);
        }
    }

    /**
     * @param array $row A stored row, its attributes decoded
     * @return array
     */
    public static function shape(array $row)
    {
        return [
            'uuid' => strtolower($row['uuid']),
            'module' => $row['module'] ?? null,
            'name' => $row['name'],
            'template_uuid' => $row['template_uuid'] ?? null,
            'template_version' => isset($row['template_version']) ? (int)$row['template_version'] : null,
            'meta_category' => (string)($row['meta_category'] ?? ''),
            'description' => (string)($row['description'] ?? ''),
            'comment' => (string)($row['comment'] ?? ''),
            'attributes' => is_array($row['attributes'] ?? null) ? $row['attributes'] : [],
            'created' => $row['created'] ?? null,
        ];
    }

    /**
     * @param array $record As shape() gives it
     * @return array The record's content, as a module answer of kind object holds it
     */
    public static function content(array $record)
    {
        return [
            'kind' => 'object',
            'name' => $record['name'],
            'meta_category' => $record['meta_category'],
            'description' => $record['description'],
            'comment' => $record['comment'],
            'attributes' => $record['attributes'],
        ];
    }

    /**
     * @param mixed $ref A uuid (its newest version) or an id
     * @return array|null The template with its elements
     */
    private function template($ref)
    {
        if (is_string($ref) && Validation::uuid($ref)) {
            $conditions = ['ObjectTemplate.uuid' => [$ref, strtolower($ref), strtoupper($ref)]];
        } elseif (is_scalar($ref) && ctype_digit((string)$ref)) {
            $conditions = ['ObjectTemplate.id' => (int)$ref];
        } else {
            return null;
        }
        $template = ClassRegistry::init('ObjectTemplate')->find('first', [
            'recursive' => -1,
            'conditions' => $conditions,
            'contain' => ['ObjectTemplateElement'],
            'order' => ['ObjectTemplate.version' => 'DESC'],
        ]);
        return empty($template) ? null : $template;
    }

    /**
     * @param string $name
     * @return array|null {uuid, version} of the newest active template so named
     */
    private function templateNamed($name)
    {
        $template = ClassRegistry::init('ObjectTemplate')->find('first', [
            'recursive' => -1,
            'fields' => ['ObjectTemplate.uuid', 'ObjectTemplate.version'],
            'conditions' => ['ObjectTemplate.name' => $name, 'ObjectTemplate.active' => 1],
            'order' => ['ObjectTemplate.version' => 'DESC'],
        ]);
        if (empty($template)) {
            return null;
        }
        return ['uuid' => strtolower($template['ObjectTemplate']['uuid']), 'version' => (int)$template['ObjectTemplate']['version']];
    }

    /**
     * @param array $content
     * @param string[] $errors
     * @return bool
     */
    private static function fits(array $content, array &$errors)
    {
        if (mb_strlen($content['name']) > self::NAME_LENGTH || mb_strlen($content['meta_category']) > self::NAME_LENGTH) {
            $errors[] = __('An object name and meta-category hold at most %s characters.', self::NAME_LENGTH);
            return false;
        }
        if (empty($content['attributes'])) {
            $errors[] = __('An object needs at least one attribute.');
            return false;
        }
        return true;
    }

    /**
     * @param string $uuid
     * @param string|null $module
     * @param array $content
     * @param array|null $template {uuid, version}
     * @return array
     */
    private static function record($uuid, $module, array $content, $template)
    {
        return [
            'uuid' => strtolower($uuid),
            'module' => $module,
            'name' => $content['name'],
            'template_uuid' => $template['uuid'] ?? null,
            'template_version' => $template['version'] ?? null,
            'meta_category' => $content['meta_category'],
            'description' => $content['description'],
            'comment' => $content['comment'],
            'attributes' => $content['attributes'],
        ];
    }
}
