<?php
App::uses('EventTemplateDependencies', 'Tools');
App::uses('EventTemplateValidator', 'Tools');
App::uses('EventTemplateImportException', 'Tools');
App::uses('CakeText', 'Utility');
App::uses('ClassRegistry', 'Utility');

/**
 * Consumes an export document (as produced by EventTemplateExporter) and
 * writes it into this MISP instance as a new or overwritten EventTemplate
 * row. Validates the envelope and runs the full structural + semantic
 * validator so import never stores a template that save() would have
 * rejected.
 *
 * Auth is the caller's responsibility — this lib is permission-agnostic
 * and does not check perm_template or org boundaries; the Phase 1.5
 * controller does that before calling in.
 *
 * Failure modes for uuid collisions are selectable via
 * $options['mode']:
 *   'fail'               (default) throw if a template with that uuid
 *                        already exists
 *   'overwrite'          update the existing row; its creator_user_id
 *                        and org_id are preserved
 *   'duplicate_as_new'   generate a fresh uuid and save as a new row
 *                        owned by the importing user/org
 */
class EventTemplateImporter
{
    const SCHEMA_VERSION = 1;

    /**
     * @param array $payload document as produced by EventTemplateExporter
     * @param array $user    CakePHP Auth user (must have id + org_id at minimum)
     * @param array $options ['mode' => 'fail' | 'overwrite' | 'duplicate_as_new']
     * @return array ['event_template_id' => int, 'event_template_uuid' => string, 'mode' => string]
     * @throws EventTemplateImportException
     * @throws EventTemplateDependencyMissingException
     */
    public function import(array $payload, array $user, array $options = array())
    {
        EventTemplateDependencies::requireAll();

        $mode = isset($options['mode']) ? (string)$options['mode'] : 'fail';
        if (!in_array($mode, array('fail', 'overwrite', 'duplicate_as_new'), true)) {
            throw new EventTemplateImportException(
                'Invalid import mode.',
                array(sprintf('unknown mode "%s"; valid: fail, overwrite, duplicate_as_new', $mode))
            );
        }

        $envErrs = $this->validateEnvelope($payload);
        if (!empty($envErrs)) {
            throw new EventTemplateImportException('Import envelope is invalid.', $envErrs);
        }

        $template = $payload['template'];
        $definition = $template['definition'];

        $validator = new EventTemplateValidator();
        $defErrs = $validator->validate($definition);
        if (!empty($defErrs)) {
            throw new EventTemplateImportException(
                'Template definition in import is invalid.',
                $defErrs
            );
        }

        $eventTemplate = ClassRegistry::init('EventTemplate');
        $existing = null;
        if (!empty($template['uuid'])) {
            $existing = $eventTemplate->find('first', array(
                'conditions' => array('EventTemplate.uuid' => strtolower($template['uuid'])),
                'recursive' => -1,
            ));
        }

        if (!empty($existing) && $mode === 'fail') {
            throw new EventTemplateImportException(
                'Template with this uuid already exists on this instance.',
                array(sprintf(
                    'uuid %s already exists (id=%d); retry with mode=overwrite or mode=duplicate_as_new',
                    $template['uuid'],
                    (int)$existing['EventTemplate']['id']
                ))
            );
        }

        $row = array(
            'name' => (string)$template['name'],
            'description' => isset($template['description']) ? $template['description'] : null,
            'distribution' => isset($template['distribution']) ? (int)$template['distribution'] : 0,
            'active' => !isset($template['active']) ? 1 : ($template['active'] ? 1 : 0),
            'definition' => $definition,
        );

        if (!empty($existing) && $mode === 'overwrite') {
            $eventTemplate->id = (int)$existing['EventTemplate']['id'];
            $row['id'] = $eventTemplate->id;
            // preserve original ownership
            $row['uuid'] = $existing['EventTemplate']['uuid'];
            $row['org_id'] = (int)$existing['EventTemplate']['org_id'];
            $row['creator_user_id'] = (int)$existing['EventTemplate']['creator_user_id'];
        } else {
            $eventTemplate->create();
            if (!empty($existing) && $mode === 'duplicate_as_new') {
                $row['uuid'] = strtolower(CakeText::uuid());
            } else {
                $row['uuid'] = strtolower((string)$template['uuid']);
            }
            $row['org_id'] = isset($user['org_id']) ? (int)$user['org_id'] : 0;
            $row['creator_user_id'] = isset($user['id']) ? (int)$user['id'] : 0;
        }

        $ok = $eventTemplate->save(array('EventTemplate' => $row));
        if (!$ok) {
            throw new EventTemplateImportException(
                'Failed to persist imported template.',
                $this->flattenValidationErrors($eventTemplate->validationErrors)
            );
        }

        $savedId = (int)$eventTemplate->id;
        $saved = $eventTemplate->find('first', array(
            'conditions' => array('EventTemplate.id' => $savedId),
            'recursive' => -1,
            'fields' => array('EventTemplate.id', 'EventTemplate.uuid'),
        ));
        return array(
            'event_template_id' => $savedId,
            'event_template_uuid' => isset($saved['EventTemplate']['uuid'])
                ? (string)$saved['EventTemplate']['uuid']
                : '',
            'mode' => (!empty($existing) && $mode === 'overwrite')
                ? 'overwrite'
                : ((!empty($existing) && $mode === 'duplicate_as_new') ? 'duplicate_as_new' : 'new'),
        );
    }

    private function validateEnvelope(array $payload)
    {
        $errors = array();

        if (!isset($payload['_meta']) || !is_array($payload['_meta'])) {
            $errors[] = '_meta block is missing';
        } else {
            $sv = isset($payload['_meta']['event_template_schema_version'])
                ? (int)$payload['_meta']['event_template_schema_version']
                : 0;
            if ($sv !== self::SCHEMA_VERSION) {
                $errors[] = sprintf(
                    '_meta.event_template_schema_version is %d; this importer handles %d',
                    $sv, self::SCHEMA_VERSION
                );
            }
        }

        if (!isset($payload['template']) || !is_array($payload['template'])) {
            $errors[] = 'template block is missing';
            return $errors;
        }
        $t = $payload['template'];
        foreach (array('uuid', 'name', 'definition') as $req) {
            if (!isset($t[$req])) {
                $errors[] = sprintf('template.%s is missing', $req);
            }
        }
        if (isset($t['definition']) && !is_array($t['definition'])) {
            $errors[] = 'template.definition must be an object';
        }
        if (isset($t['distribution']) && !in_array((int)$t['distribution'], array(0, 1), true)) {
            $errors[] = 'template.distribution must be 0 (org only) or 1 (community)';
        }
        if (isset($t['uuid']) && !preg_match('/^[0-9a-fA-F-]{36}$/', (string)$t['uuid'])) {
            $errors[] = 'template.uuid is not a well-formed UUID';
        }
        return $errors;
    }

    private function flattenValidationErrors(array $validationErrors)
    {
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
        return $out;
    }
}
