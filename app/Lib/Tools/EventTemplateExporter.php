<?php
App::uses('ClassRegistry', 'Utility');

/**
 * Serialises an event-template row (with its JSON `definition` already
 * decoded to an array by EventTemplate::afterFind) into the export shape
 * documented in PRD §13. Output is a PHP array; callers json_encode() it
 * at the boundary.
 *
 * Shape:
 *   {
 *     "_meta": {
 *       "misp_version":                   "2.5.36",
 *       "exported_at":                    "2026-04-23T10:30:25+00:00",
 *       "event_template_schema_version":  1
 *     },
 *     "template": {
 *       "uuid":        "...",
 *       "name":        "...",
 *       "description": "...",
 *       "version":     3,
 *       "distribution": 0,
 *       "active":      true,
 *       "definition":  { ... }        // PRD §7
 *     }
 *   }
 *
 * Creator and org are deliberately omitted — they belong to the instance
 * that produced the file and are not meaningful across instances. On
 * import the importing user/org become the new owner (see Importer).
 */
class EventTemplateExporter
{
    /**
     * @param array $templateRow row as returned by EventTemplate->find(...)
     *                            — expects at least the EventTemplate key
     *                            with uuid, name, description, version,
     *                            distribution, active, definition fields.
     * @return array
     */
    public function export(array $templateRow)
    {
        if (!isset($templateRow['EventTemplate'])) {
            throw new InvalidArgumentException(
                'EventTemplateExporter::export() expects a row keyed by "EventTemplate".'
            );
        }
        $t = $templateRow['EventTemplate'];

        $definition = isset($t['definition']) ? $t['definition'] : array();
        if (is_string($definition)) {
            $decoded = json_decode($definition, true);
            if (is_array($decoded)) {
                $definition = $decoded;
            }
        }

        return array(
            '_meta' => array(
                'misp_version' => $this->mispVersionString(),
                'exported_at' => gmdate('c'),
                'event_template_schema_version' => 1,
            ),
            'template' => array(
                'uuid' => isset($t['uuid']) ? (string)$t['uuid'] : '',
                'name' => isset($t['name']) ? (string)$t['name'] : '',
                'description' => isset($t['description']) ? $t['description'] : null,
                'version' => isset($t['version']) ? (int)$t['version'] : 1,
                'distribution' => isset($t['distribution']) ? (int)$t['distribution'] : 0,
                'active' => !isset($t['active']) ? true : (bool)$t['active'],
                'default' => !empty($t['default']),
                'definition' => $definition,
            ),
        );
    }

    private function mispVersionString()
    {
        try {
            $appModel = ClassRegistry::init('AppModel');
            $v = $appModel->checkMISPVersion();
            if (is_array($v) && isset($v['major'], $v['minor'], $v['hotfix'])) {
                return sprintf('%d.%d.%d', (int)$v['major'], (int)$v['minor'], (int)$v['hotfix']);
            }
        } catch (Exception $e) {
            // fall through
        }
        return 'unknown';
    }
}
