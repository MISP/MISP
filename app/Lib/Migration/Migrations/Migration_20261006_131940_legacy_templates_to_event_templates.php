<?php

App::uses('AbstractMigration', 'Migration');
App::uses('CakeText', 'Utility');
App::uses('JsonTool', 'Tools');
App::uses('Model', 'Model');

/**
 * Convert the legacy templates into event templates and drop their tables
 */
class Migration_20261006_131940_legacy_templates_to_event_templates extends AbstractMigration
{
    public $description = 'Convert the legacy templates into event templates and drop their tables';

    /**
     * Nothing the session data is built from changes.
     *
     * @var bool
     */
    public $requiresLogout = false;

    /**
     * templates goes first, so a retry after a partial drop finds nothing
     * left to convert.
     */
    const TABLES = array(
        'templates',
        'template_elements',
        'template_element_attributes',
        'template_element_files',
        'template_element_texts',
        'template_tags',
    );

    /**
     * The object a legacy complex attribute becomes, when its template is
     * installed.
     */
    const COMPLEX_OBJECTS = array(
        'file' => array(
            'uuid' => '688c46fb-5edb-40a3-8273-1af7923e2215',
            'name' => 'file',
            'relations' => array('filename', 'md5', 'sha1', 'sha256'),
        ),
        'cnc' => array(
            'uuid' => '43b3b146-77eb-4931-b4cc-b66c60f28734',
            'name' => 'domain-ip',
            'relations' => array('domain', 'hostname', 'ip'),
        ),
    );

    /**
     * The attribute fields a legacy complex attribute expands into otherwise.
     */
    const COMPLEX_TYPES = array(
        'file' => array(
            'Filename' => 'filename',
            'MD5' => 'md5',
            'SHA1' => 'sha1',
            'SHA256' => 'sha256',
            'Filename | MD5' => 'filename|md5',
            'Filename | SHA1' => 'filename|sha1',
            'Filename | SHA256' => 'filename|sha256',
        ),
        'cnc' => array(
            'URL' => 'url',
            'Domain' => 'domain',
            'Hostname' => 'hostname',
            'IP destination' => 'ip-dst',
        ),
    );

    /** @var EventTemplate */
    private $EventTemplate;

    /** @var array|false|null The first active site admin, false if none */
    private $owner;

    /** @var array Legacy rows, per table */
    private $rows = array();

    /**
     * Turn every legacy template an organisation authored into an active
     * event template. The MISP-shipped seed set is left out, the event
     * template library ships its successors. A template that cannot be
     * converted, or whose name an event template already has, is not saved;
     * its converted definition goes to the log instead, so dropping the
     * tables loses nothing and a bad row cannot hold the upgrade back.
     *
     * @return bool
     */
    public function beforeUp()
    {
        if (!$this->inspector()->hasTable('templates')) {
            return true;
        }
        $this->EventTemplate = ClassRegistry::init('EventTemplate');

        $converted = array();
        $notConverted = array();
        foreach ($this->legacyRows('templates') as $template) {
            if (strtolower(trim((string)$template['org'])) === 'misp') {
                continue;
            }
            $name = (string)$template['name'];
            $definition = $this->definition($template);
            $exists = $this->EventTemplate->hasAny(
                array('EventTemplate.name' => $name)
            );
            if ($exists) {
                $error = __('an event template with this name already exists');
            } else {
                $error = $this->saveEventTemplate($template, $definition);
            }
            if ($error === null) {
                $converted[] = $name;
            } else {
                $notConverted[] = $name;
                $this->logEntry(
                    __('Legacy template "%s" was not converted: %s', $name, $error),
                    JsonTool::encode($definition, true)
                );
            }
        }
        if (!empty($converted) || !empty($notConverted)) {
            $change = array();
            if (!empty($converted)) {
                $change[] = __('Converted: %s', implode(', ', $converted));
            }
            if (!empty($notConverted)) {
                $change[] = __('Not converted, definition logged separately: %s', implode(', ', $notConverted));
            }
            $this->logEntry(
                __('Converted %s of %s legacy templates into event templates.', count($converted), count($converted) + count($notConverted)),
                implode("\n", $change)
            );
        }
        return true;
    }

    /**
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
        foreach (self::TABLES as $table) {
            if ($this->inspector()->hasTable($table)) {
                $schema->dropTable($table);
            }
        }
    }

    /**
     * @param array $template A templates row
     * @param array $definition
     * @return string|null Why it was not saved, null once it is
     */
    private function saveEventTemplate(array $template, array $definition)
    {
        $owner = $this->owner();
        if ($owner === false) {
            return __('there is no active site admin to own it');
        }
        try {
            $this->EventTemplate->create();
            $saved = $this->EventTemplate->save(array('EventTemplate' => array(
                'uuid' => $definition['uuid'],
                'name' => $definition['name'],
                'description' => $definition['description'],
                'distribution' => $definition['event_defaults']['distribution'],
                'active' => 1,
                'misp_default' => 0,
                'org_id' => $this->orgId((string)$template['org'], $owner['org_id']),
                'creator_user_id' => $owner['id'],
                'definition' => $definition,
            )));
        } catch (Exception $e) {
            return $e->getMessage();
        }
        if (empty($saved)) {
            return JsonTool::encode($this->EventTemplate->validationErrors);
        }
        return null;
    }

    /**
     * @param array $template A templates row
     * @return array An event-template-v1 definition
     */
    private function definition(array $template)
    {
        $structure = array();
        $section = null;
        $counters = array('sec' => 0, 'note' => 0, 'attr' => 0, 'file' => 0, 'obj' => 0);

        $elements = $this->legacyRows('template_elements', 'template_id', $template['id']);
        usort($elements, function ($a, $b) {
            return (int)$a['position'] - (int)$b['position'];
        });
        foreach ($elements as $element) {
            $kind = strtolower((string)$element['element_definition']);
            $table = array(
                'text' => 'template_element_texts',
                'attribute' => 'template_element_attributes',
                'file' => 'template_element_files',
            );
            if (!isset($table[$kind])) {
                continue;
            }
            $row = $this->legacyRows($table[$kind], 'template_element_id', $element['id']);
            if (empty($row)) {
                continue;
            }
            $row = $row[0];

            if ($kind === 'text') {
                $section = 'sec_' . ++$counters['sec'];
                $field = array(
                    'type' => 'section',
                    'id' => $section,
                    'label' => $this->label($row['name'], 'Section %d', $counters['sec']),
                );
                if (trim((string)$row['text']) !== '') {
                    $field['help'] = trim((string)$row['text']);
                }
                $structure[] = $field;
                continue;
            }

            if ($kind === 'attribute' && !empty($row['complex'])) {
                $object = $this->complexObject((string)$row['type']);
                if ($object !== null) {
                    $field = array(
                        'type' => 'object_field',
                        'id' => 'obj_' . ++$counters['obj'],
                        'label' => $this->label($row['name'], 'Object %d', $counters['obj']),
                        'mandatory' => !empty($row['mandatory']),
                        'repeatable' => true,
                        'object_template' => array(
                            'uuid' => $object['uuid'],
                            'name' => $object['name'],
                            'minimum_version' => $object['version'],
                        ),
                        'relations' => array_map(function ($relation) {
                            return array('object_relation' => $relation);
                        }, $object['relations']),
                    );
                    $structure[] = $this->place($field, $section, $row['description']);
                    continue;
                }

                $content = sprintf(
                    '**%s** — capture any combination of the matching subtypes below.',
                    (string)$row['name']
                );
                if (!empty($row['description'])) {
                    $content .= "\n\n" . (string)$row['description'];
                }
                $structure[] = array(
                    'type' => 'text_block',
                    'id' => 'note_' . ++$counters['note'],
                    'content' => $content,
                );
                $key = strtolower(trim((string)$row['type']));
                $types = isset(self::COMPLEX_TYPES[$key])
                    ? self::COMPLEX_TYPES[$key]
                    : array((string)$row['type'] => 'text');
                foreach ($types as $label => $type) {
                    $field = array(
                        'type' => 'attribute_field',
                        'id' => 'attr_' . ++$counters['attr'],
                        'label' => (string)$row['name'] . ' — ' . $label,
                        'mandatory' => false,
                        'repeatable' => true,
                        'misp' => array(
                            'category' => (string)$row['category'],
                            'type' => $type,
                            'to_ids_default' => !empty($row['to_ids']),
                        ),
                    );
                    $structure[] = $this->place($field, $section, null);
                }
                continue;
            }

            if ($kind === 'attribute') {
                $field = array(
                    'type' => 'attribute_field',
                    'id' => 'attr_' . ++$counters['attr'],
                    'label' => $this->label($row['name'], 'Attribute %d', $counters['attr']),
                    'mandatory' => !empty($row['mandatory']),
                    'repeatable' => !empty($row['batch']),
                    'misp' => array(
                        'category' => (string)$row['category'],
                        'type' => (string)$row['type'],
                        'to_ids_default' => !empty($row['to_ids']),
                    ),
                );
                $structure[] = $this->place($field, $section, $row['description']);
                continue;
            }

            $field = array(
                'type' => 'file_field',
                'id' => 'file_' . ++$counters['file'],
                'label' => $this->label($row['name'], 'File %d', $counters['file']),
                'mandatory' => !empty($row['mandatory']),
                'repeatable' => !empty($row['batch']),
                'as' => !empty($row['malware']) ? 'malware-sample' : 'attachment',
            );
            $structure[] = $this->place($field, $section, $row['description']);
        }

        $eventDefaults = array(
            'distribution' => ((int)$template['share'] === 1) ? 1 : 0,
        );
        $tagIds = array_column(
            $this->legacyRows('template_tags', 'template_id', $template['id']),
            'tag_id'
        );
        if (!empty($tagIds)) {
            $names = ClassRegistry::init('Tag')->find('list', array(
                'recursive' => -1,
                'conditions' => array('Tag.id' => $tagIds),
                'fields' => array('Tag.id', 'Tag.name'),
                'order' => array('Tag.id'),
            ));
            foreach ($names as $tagName) {
                $eventDefaults['tags'][] = array('name' => (string)$tagName, 'locked' => false);
            }
        }

        return array(
            'schema_version' => 1,
            'uuid' => CakeText::uuid(),
            'name' => (string)$template['name'],
            'description' => (string)$template['description'],
            'event_defaults' => $eventDefaults,
            'structure' => $structure,
        );
    }

    /**
     * The schema wants a label on every interactive element.
     *
     * @param string|null $name
     * @param string $fallback
     * @param int $counter
     * @return string
     */
    private function label($name, $fallback, $counter)
    {
        $name = (string)$name;
        return $name === '' ? sprintf($fallback, $counter) : $name;
    }

    /**
     * @param array $field
     * @param string|null $section
     * @param string|null $help
     * @return array
     */
    private function place(array $field, $section, $help)
    {
        if ($section !== null) {
            $field['parent'] = $section;
        }
        if (!empty($help)) {
            $field['help'] = (string)$help;
        }
        return $field;
    }

    /**
     * @param string $type The legacy complex type, File or CnC
     * @return array|null The installed object template, null if there is none
     */
    private function complexObject($type)
    {
        $key = strtolower(trim($type));
        if (!isset(self::COMPLEX_OBJECTS[$key])) {
            return null;
        }
        $object = self::COMPLEX_OBJECTS[$key];
        $installed = ClassRegistry::init('ObjectTemplate')->find('first', array(
            'recursive' => -1,
            'conditions' => array(
                'ObjectTemplate.uuid' => $object['uuid'],
                'ObjectTemplate.active' => true,
            ),
            'fields' => array('ObjectTemplate.version'),
            'order' => array('ObjectTemplate.version' => 'DESC'),
        ));
        if (empty($installed)) {
            return null;
        }
        $object['version'] = (int)$installed['ObjectTemplate']['version'];
        return $object;
    }

    /**
     * @return array|false
     */
    private function owner()
    {
        if ($this->owner === null) {
            $admin = ClassRegistry::init('User')->find('first', array(
                'recursive' => -1,
                'contain' => array('Role'),
                'conditions' => array(
                    'Role.perm_site_admin' => 1,
                    'User.disabled' => 0,
                ),
                'fields' => array('User.id', 'User.org_id'),
                'order' => array('User.id' => 'ASC'),
            ));
            $this->owner = empty($admin) ? false : array(
                'id' => (int)$admin['User']['id'],
                'org_id' => (int)$admin['User']['org_id'],
            );
        }
        return $this->owner;
    }

    /**
     * Legacy templates name their organisation rather than point at it.
     *
     * @param string $name
     * @param int $fallback
     * @return int
     */
    private function orgId($name, $fallback)
    {
        if (trim($name) === '') {
            return $fallback;
        }
        $org = ClassRegistry::init('Organisation')->find('first', array(
            'recursive' => -1,
            'conditions' => array('Organisation.name' => trim($name)),
            'fields' => array('Organisation.id'),
        ));
        return empty($org) ? $fallback : (int)$org['Organisation']['id'];
    }

    /**
     * Their models are gone, so the legacy tables are read through a bare
     * model each, once, and filtered here.
     *
     * @param string $table
     * @param string|null $column
     * @param mixed $value
     * @return array
     */
    private function legacyRows($table, $column = null, $value = null)
    {
        if (!isset($this->rows[$table])) {
            $this->rows[$table] = array();
            if ($this->inspector()->hasTable($table)) {
                $model = new Model(array('table' => $table, 'name' => 'Legacy', 'ds' => 'default'));
                $rows = $model->find('all', array('recursive' => -1, 'order' => array('Legacy.id')));
                $this->rows[$table] = array_column($rows, 'Legacy');
            }
        }
        if ($column === null) {
            return $this->rows[$table];
        }
        return array_values(array_filter($this->rows[$table], function ($row) use ($column, $value) {
            return (int)$row[$column] === (int)$value;
        }));
    }

    /**
     * @param string $title
     * @param string $change
     * @return void
     */
    private function logEntry($title, $change)
    {
        $Log = ClassRegistry::init('Log');
        $Log->create();
        $Log->saveOrFailSilently(array(
            'org' => 'SYSTEM',
            'model' => 'EventTemplate',
            'model_id' => 0,
            'email' => 'SYSTEM',
            'action' => 'update_database',
            'user_id' => 0,
            'title' => $title,
            'change' => $change,
        ));
    }
}
