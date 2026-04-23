<?php
App::uses('EventTemplateDependencies', 'Tools');
App::uses('ClassRegistry', 'Utility');

/**
 * Single authority for validating an event-template `definition` document
 * (PRD §7). Combines two layers and returns a flat list of human-readable
 * error strings; empty list means the definition is valid.
 *
 * Layer 1 — Structural (justinrainbow/json-schema)
 *   Validates against app/files/schemas/event-template-v1.schema.json.
 *   Catches everything the schema encodes: required fields, types, enums,
 *   the non-empty-label rule on every interactive element, the
 *   info_template variable grammar, and the distribution=4 →
 *   sharing_group_id dependency.
 *
 * Layer 2 — Semantic (DB-aware and cross-element)
 *   - no duplicate element ids
 *   - object_reference.from/to point at real object_field ids
 *   - attribute_field.misp.category + type is a valid MISP combo
 *     (against MispAttribute::categoryDefinitions)
 *   - object_field.object_template.uuid is installed on this
 *     instance at version >= pinned_version
 *   - info_template `{{field:<id>}}` refs resolve to element ids
 *
 * Both layers run every call; the combined list lets the caller fix
 * everything in one pass instead of round-tripping through structural-
 * then-semantic. Semantic checks are defensive against missing keys so
 * running them on a structurally-invalid document does not crash.
 *
 * Asserts `justinrainbow/json-schema` is installed at first use. If
 * missing, EventTemplateDependencyMissingException propagates so the
 * caller (Phase 1.5 controllers) can render an admin-instruction page.
 */
class EventTemplateValidator
{
    /** @var object|null cached decoded schema (process-lifetime) */
    private static $schema = null;

    /**
     * @param array $definition event-template definition (PRD §7)
     * @return string[] error messages; empty = valid
     */
    public function validate(array $definition)
    {
        return array_merge(
            $this->validateStructure($definition),
            $this->validateSemantic($definition)
        );
    }

    private function validateStructure(array $definition)
    {
        EventTemplateDependencies::requireSome(array('justinrainbow/json-schema'));

        $schema = self::loadSchema();
        // justinrainbow expects stdClass trees; round-trip through JSON
        // to convert the associative array we were given.
        $data = json_decode(json_encode($definition));

        $validator = new \JsonSchema\Validator();
        $validator->validate($data, $schema);
        if ($validator->isValid()) {
            return array();
        }

        $errors = array();
        foreach ($validator->getErrors() as $err) {
            $where = (isset($err['property']) && $err['property'] !== '')
                ? $err['property']
                : '(root)';
            $msg = isset($err['message']) ? $err['message'] : 'unspecified schema error';
            $errors[] = sprintf('[schema] %s: %s', $where, $msg);
        }
        return $errors;
    }

    private static function loadSchema()
    {
        if (self::$schema !== null) {
            return self::$schema;
        }
        $path = APP . 'files' . DS . 'schemas' . DS . 'event-template-v1.schema.json';
        $json = @file_get_contents($path);
        if ($json === false) {
            throw new RuntimeException('Unable to read event-template schema at ' . $path);
        }
        $decoded = json_decode($json);
        if ($decoded === null) {
            throw new RuntimeException(
                'event-template schema is not valid JSON: ' . json_last_error_msg()
            );
        }
        self::$schema = $decoded;
        return self::$schema;
    }

    private function validateSemantic(array $definition)
    {
        $errors = array();

        if (!isset($definition['structure']) || !is_array($definition['structure'])) {
            // Structure layer already flagged this; no semantic work to do.
            return $errors;
        }

        // First pass: collect ids, detect duplicates, index object_fields.
        $elementsById = array();
        $objectFieldIds = array();
        $allElementIds = array();

        foreach ($definition['structure'] as $element) {
            if (!is_array($element) || !isset($element['type'])) {
                continue;
            }
            $id = isset($element['id']) ? $element['id'] : null;
            if ($id === null || $id === '') {
                continue;
            }
            if (isset($elementsById[$id])) {
                $errors[] = sprintf('duplicate element id: %s', $id);
                continue;
            }
            $elementsById[$id] = $element;
            $allElementIds[] = $id;
            if ($element['type'] === 'object_field') {
                $objectFieldIds[$id] = true;
            }
        }

        // Second pass: cross-references and DB-backed checks.
        foreach ($definition['structure'] as $element) {
            if (!is_array($element) || !isset($element['type'])) {
                continue;
            }
            $type = $element['type'];
            $id = isset($element['id']) ? $element['id'] : '?';

            if ($type === 'object_reference') {
                foreach (array('from', 'to') as $endpoint) {
                    $ref = isset($element[$endpoint]) ? $element[$endpoint] : null;
                    if ($ref === null) {
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
                $misp = (isset($element['misp']) && is_array($element['misp'])) ? $element['misp'] : array();
                $category = isset($misp['category']) ? $misp['category'] : null;
                $attrType = isset($misp['type']) ? $misp['type'] : null;
                if ($category === null || $attrType === null) {
                    continue;
                }
                if (!$this->isValidCategoryType($category, $attrType)) {
                    $errors[] = sprintf(
                        'attribute_field "%s": type "%s" is not valid in category "%s"',
                        $id, $attrType, $category
                    );
                }
            } elseif ($type === 'object_field') {
                $ot = (isset($element['object_template']) && is_array($element['object_template']))
                    ? $element['object_template']
                    : array();
                $uuid = isset($ot['uuid']) ? $ot['uuid'] : null;
                $pinned = isset($ot['pinned_version']) ? (int)$ot['pinned_version'] : null;
                if ($uuid === null || $pinned === null) {
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

        // info_template {{field:<id>}} references must resolve to element ids.
        $infoTemplate = isset($definition['event_defaults']['info_template'])
            ? $definition['event_defaults']['info_template']
            : null;
        if (is_string($infoTemplate) && $infoTemplate !== '') {
            $matches = array();
            preg_match_all('/\{\{field:([a-zA-Z_][a-zA-Z0-9_]*)\}\}/', $infoTemplate, $matches);
            if (!empty($matches[1])) {
                foreach (array_unique($matches[1]) as $refId) {
                    if (!in_array($refId, $allElementIds, true)) {
                        $errors[] = sprintf('info_template references unknown field id: %s', $refId);
                    }
                }
            }
        }

        return $errors;
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
                'ObjectTemplate.uuid' => strtolower((string)$uuid),
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
