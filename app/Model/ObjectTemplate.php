<?php
App::uses('AppModel', 'Model');
App::uses('FileAccessTool', 'Tools');

/**
 * @property ObjectTemplateElement $ObjectTemplateElement
 */
class ObjectTemplate extends AppModel
{
    public $actsAs = array(
        'AuditLog',
            'Containable',
            'SysLogLogable.SysLogLogable' => array(	// TODO Audit, logable
                'userModel' => 'User',
                'userKey' => 'user_id',
                'change' => 'full'),
    );

    public $belongsTo = array(
        'User' => array(
            'className' => 'User',
            'foreignKey' => 'user_id'
        ),
        'Organisation' => array(
            'className' => 'Organisation',
            'foreignKey' => 'org_id'
        )
    );
    public $hasMany = array(
        'ObjectTemplateElement' => array(
            'className' => 'ObjectTemplateElement',
            'dependent' => true,
        )
    );

    const OBJECTS_DIR = APP . 'files/misp-objects/objects';

    public function afterFind($results, $primary = false)
    {
        foreach ($results as $k => $result) {
            if (isset($result['ObjectTemplate']['requirements'])) {
                $results[$k]['ObjectTemplate']['requirements'] = json_decode($result['ObjectTemplate']['requirements'], true);
            }
        }
        return $results;
    }

    public function beforeSave($options = array())
    {
        $this->data['ObjectTemplate']['requirements'] = empty($this->data['ObjectTemplate']['requirements']) ? '[]' : json_encode($this->data['ObjectTemplate']['requirements']);
        return true;
    }

    public function update($user = false, $type = false, $force = false)
    {
        $directories = $this->getTemplateDirectoryPaths();
        foreach ($directories as $k => $dir) {
            $dir = str_replace(self::OBJECTS_DIR, '', $dir);
            $directories[$k] = $dir;
        }
        $updated = array();
        foreach ($directories as $dir) {
            if ($type && '/' . $type != $dir) {
                continue;
            }
            if (!file_exists(self::OBJECTS_DIR . DS . $dir . DS . 'definition.json')) {
                continue;
            }
            $template = FileAccessTool::readJsonFromFile(self::OBJECTS_DIR . DS . $dir . DS . 'definition.json');
            if (!isset($template['version'])) {
                $template['version'] = 1;
            }
            $current = $this->find('first', array(
                'fields' => array('MAX(version) AS version', 'uuid'),
                'conditions' => array('uuid' => $template['uuid']),
                'recursive' => -1,
                'group' => array('uuid')
            ));
            if (!empty($current)) {
                $current['ObjectTemplate']['version'] = $current[0]['version'];
            }
            if ($force || empty($current) || $template['version'] > $current['ObjectTemplate']['version']) {
                $result = $this->__updateObjectTemplate($template, $current, $user);
                if ($result === true) {
                    $temp = array('name' => $template['name'], 'new' => $template['version']);
                    if (!empty($current)) {
                        $temp['old'] = $current['ObjectTemplate']['version'];
                    }
                    $updated['success'][] = $temp;
                } else {
                    $updated['fails'][] = array('name' => $template['name'], 'fail' => json_encode($result));
                }
            }
        }
        return $updated;
    }

    private function __updateObjectTemplate($template, $current, $user = false)
    {
        $template['requirements'] = array();
        $requirementFields = array('required', 'requiredOneOf');
        foreach ($requirementFields as $field) {
            if (isset($template[$field])) {
                $template['requirements'][$field] = $template[$field];
            }
        }
        if (!empty($user)) {
            $template['user_id'] = $user['id'];
            $template['org_id'] = $user['org_id'];
        } else {
            $template['user_id'] = 0;
            $template['org_id'] = 0;
        }
        $template['fixed'] = 1;
        $this->create();
        $result = $this->save($template);
        if (!$result) {
            return $this->validationErrors;
        }
        $id = $this->id;
        $this->setActive($id);

        $attributes = [];
        foreach ($template['attributes'] as $k => $attribute) {
            $attribute = $this->__convertJSONToElement($attribute);
            $attribute['object_relation'] = $k;
            $attribute['object_template_id'] = $id;
            $attributes[] = ['ObjectTemplateElement' => $attribute];
        }
        $this->ObjectTemplateElement->saveMany($attributes);

        return true;
    }

    private function __convertJSONToElement($attribute)
    {
        $result = array();
        $translation_table = array(
            'misp-usage-frequency' => 'frequency',
            'misp-attribute' => 'type',
            'description' => 'description',
            'ui-priority' => 'ui-priority',
            'type' => 'type',
            'disable_correlation' => 'disable_correlation',
            'object_relation' => 'object_relation',
            'categories' => 'categories',
            'sane_default' => 'sane_default',
            'values_list' => 'values_list',
            'multiple' => 'multiple'
        );
        foreach ($translation_table as $from => $to) {
            if (isset($attribute[$from])) {
                $result[$to] = $attribute[$from];
            }
        }
        return $result;
    }

    public function checkTemplateConformity($template, $attributes)
    {
        if (!empty($template['ObjectTemplate']['requirements'])) {
            // check for all required attributes
            if (!empty($template['ObjectTemplate']['requirements']['required'])) {
                foreach ($template['ObjectTemplate']['requirements']['required'] as $requiredField) {
                    $found = false;
                    foreach ($attributes['Attribute'] as $attribute) {
                        if ($attribute['object_relation'] == $requiredField) {
                            $found = true;
                        }
                    }
                    if (!$found) {
                        return 'Could not save the object as a required attribute is not set (' . $requiredField . ')';
                    }
                }
            }
            // check for all required one of attributes
            if (!empty($template['ObjectTemplate']['requirements']['requiredOneOf'])) {
                $found = false;
                foreach ($template['ObjectTemplate']['requirements']['requiredOneOf'] as $requiredField) {
                    foreach ($attributes['Attribute'] as $attribute) {
                        if ($attribute['object_relation'] == $requiredField) {
                            $found = true;
                        }
                    }
                }
                if (!$found) {
                    return 'Could not save the object as it requires at least one of the following attributes to be set: ' . implode(', ', $template['ObjectTemplate']['requirements']['requiredOneOf']);
                }
            }
        }
        // check the multiple flag is adhered to
        foreach ($template['ObjectTemplateElement'] as $template_attribute) {
            if ($template_attribute['multiple'] !== true) {
                $found_relations = array();
                foreach ($attributes['Attribute'] as $attribute) {
                    if ($attribute['object_relation'] == $template_attribute['object_relation']) {
                        if (!isset($found_relations[$attribute['object_relation']])) {
                            $found_relations[$attribute['object_relation']] = true;
                        } else {
                            return 'Could not save the object as a unique relationship within the object was assigned to more than one attribute. This is only allowed if the multiple flag is set in the object template.';
                        }
                    }
                }
            }
        }
        return true;
    }

    /**
     * @param array $attributeTypes Array of attribute types to check, can contains multiple types
     * @return array
     */
    public function fetchPossibleTemplatesBasedOnTypes(array $attributeTypes)
    {
        $uniqueAttributeTypes = array_unique($attributeTypes, SORT_REGULAR);
        $potentialTemplateIds = $this->find('column', array(
            'recursive' => -1,
            'fields' => array(
                'ObjectTemplate.id',
            ),
            'conditions' => array(
                'ObjectTemplate.active' => true,
                'ObjectTemplateElement.type' => $uniqueAttributeTypes,
            ),
            'joins' => array(
                array(
                    'table' => 'object_template_elements',
                    'alias' => 'ObjectTemplateElement',
                    'type' => 'RIGHT',
                    'fields' => array('ObjectTemplateElement.object_relation', 'ObjectTemplateElement.type'),
                    'conditions' => array('ObjectTemplate.id = ObjectTemplateElement.object_template_id')
                )
            ),
            'group' => 'ObjectTemplate.id',
        ));

        $templates = $this->find('all', [
            'recursive' => -1,
            'conditions' => ['id' => $potentialTemplateIds],
            'contain' => ['ObjectTemplateElement' => ['fields' => ['object_relation', 'type', 'multiple']]]
        ]);

        foreach ($templates as $i => $template) {
            $res = $this->checkTemplateConformityBasedOnTypes($template, $attributeTypes);
            $templates[$i]['ObjectTemplate']['compatibility'] = $res['valid'] ? true : $res['missingTypes'];
            $templates[$i]['ObjectTemplate']['invalidTypes'] = $res['invalidTypes'];
            $templates[$i]['ObjectTemplate']['invalidTypesMultiple'] = $res['invalidTypesMultiple'];
        }

        usort($templates, function($a, $b) {
            if ($a['ObjectTemplate']['id'] == $b['ObjectTemplate']['id']) {
                return 0;
            } else if (is_array($a['ObjectTemplate']['compatibility']) && is_array($b['ObjectTemplate']['compatibility'])) {
                return count($a['ObjectTemplate']['compatibility']) > count($b['ObjectTemplate']['compatibility']) ? 1 : -1;
            } else if (is_array($a['ObjectTemplate']['compatibility']) && !is_array($b['ObjectTemplate']['compatibility'])) {
                return 1;
            } else if (!is_array($a['ObjectTemplate']['compatibility']) && is_array($b['ObjectTemplate']['compatibility'])) {
                return -1;
            } else { // sort based on invalidTypes count
                return count($a['ObjectTemplate']['invalidTypes']) > count($b['ObjectTemplate']['invalidTypes']) ? 1 : -1;
            }
        });

        return array('templates' => $templates, 'types' => $uniqueAttributeTypes);
    }

    /**
     * @param array $template
     * @param array $attributeTypes Array of attribute types to check, can contains multiple types
     * @return array
     */
    public function checkTemplateConformityBasedOnTypes(array $template, array $attributeTypes)
    {
        $to_return = array('valid' => true, 'missingTypes' => array());
        if (!empty($template['ObjectTemplate']['requirements'])) {
            // construct array containing ObjectTemplateElement with object_relation as key for faster search
            $elementsByObjectRelationName = array_column($template['ObjectTemplateElement'], null, 'object_relation');

            // check for all required attributes
            if (!empty($template['ObjectTemplate']['requirements']['required'])) {
                foreach ($template['ObjectTemplate']['requirements']['required'] as $requiredField) {
                    $requiredType = $elementsByObjectRelationName[$requiredField]['type'];
                    $found = in_array($requiredType, $attributeTypes, true);
                    if (!$found) {
                        $to_return = array('valid' => false, 'missingTypes' => array($requiredType));
                    }
                }
            }
            // check for all required one of attributes
            if (!empty($template['ObjectTemplate']['requirements']['requiredOneOf'])) {
                $found = false;
                $allRequiredTypes = array();
                foreach ($template['ObjectTemplate']['requirements']['requiredOneOf'] as $requiredField) {
                    $requiredType = $elementsByObjectRelationName[$requiredField]['type'] ?? null;
                    $allRequiredTypes[] = $requiredType;
                    if (!$found) {
                        $found = in_array($requiredType, $attributeTypes, true);
                    }
                }
                if (!$found) {
                    $to_return = array('valid' => false, 'missingTypes' => $allRequiredTypes);
                }
            }
        }

        // at this point, an object could created; checking if all attribute are valid
        $valid_types = array();
        $to_return['invalidTypes'] = array();
        $to_return['invalidTypesMultiple'] = array();
        foreach ($template['ObjectTemplateElement'] as $templateElement) {
            $valid_types[$templateElement['type']] = $templateElement['multiple'];
        }
        $check_for_multiple_type = array();
        foreach ($attributeTypes as $attributeType) {
            if (isset($valid_types[$attributeType])) {
                if (!$valid_types[$attributeType]) { // is not multiple
                    if (isset($check_for_multiple_type[$attributeType])) {
                        $to_return['invalidTypesMultiple'][] = $attributeType;
                    } else {
                        $check_for_multiple_type[$attributeType] = 1;
                    }
                }
            } else {
                $to_return['invalidTypes'][] = $attributeType;
            }
        }
        $to_return['invalidTypes'] = array_unique($to_return['invalidTypes'], SORT_REGULAR);
        $to_return['invalidTypesMultiple'] = array_unique($to_return['invalidTypesMultiple'], SORT_REGULAR);
        if (!empty($to_return['invalidTypesMultiple'])) {
            $to_return['valid'] = false;
        }
        return $to_return;
    }

    // simple test to see if there are any object templates - if not trigger update
    public function populateIfEmpty(array $user)
    {
        if (!$this->hasAny()) {
            $this->update($user);
        }
    }

    public function setActive($id)
    {
        $template = $this->find('first', array(
            'recursive' => -1,
            'conditions' => array('ObjectTemplate.id' => $id),
            'fields' => ['ObjectTemplate.id', 'ObjectTemplate.uuid', 'ObjectTemplate.active'],
        ));
        if (empty($template)) {
            return false;
        }
        if ($template['ObjectTemplate']['active']) {
            $template['ObjectTemplate']['active'] = 0;
            $this->save($template, true, ['active']);
            return 0;
        }
        $similar_templates = $this->find('all', array(
            'recursive' => -1,
            'fields' => ['ObjectTemplate.id'],
            'conditions' => array(
                'ObjectTemplate.uuid' => $template['ObjectTemplate']['uuid'],
                'NOT' => array(
                    'ObjectTemplate.id' => $template['ObjectTemplate']['id']
                )
            )
        ));
        $template['ObjectTemplate']['active'] = 1;
        $this->save($template, true, ['active']);
        foreach ($similar_templates as $st) {
            $st['ObjectTemplate']['active'] = 0;
            $this->save($st, true, ['active']);
        }
        return 1;
    }

    public function getRawFromDisk($uuidOrName)
    {
        if (Validation::uuid($uuidOrName)) {
            foreach ($this->readTemplatesFromDisk() as $templateFromDisk) {
                if ($templateFromDisk['uuid'] === $uuidOrName) {
                    return $templateFromDisk;
                }
            }
        } else {
            $allTemplateNames = $this->getTemplateDirectoryPaths(false);
            if (in_array($uuidOrName, $allTemplateNames, true)) { // ensure the path is not out of scope
                return $this->readTemplateFromDisk($this->getFullPathFromTemplateName($uuidOrName));
            }
        }
        return [];
    }

    /**
     * @throws Exception
     */
    private function readTemplateFromDisk($path)
    {
        if (!file_exists($path)) {
            return false;
        }
        return FileAccessTool::readJsonFromFile($path);
    }

    /**
     * @return Generator<array>
     * @throws Exception
     */
    private function readTemplatesFromDisk()
    {
        foreach ($this->getTemplateDirectoryPaths() as $dirpath) {
            $filepath = $dirpath . DS . 'definition.json';
            $template = $this->readTemplateFromDisk($filepath);
            if (isset($template['uuid'])) {
                yield $template;
            }
        }
    }

    /**
     * @param bool $fullPath
     * @return array
     */
    private function getTemplateDirectoryPaths($fullPath=true)
    {
        App::uses('Folder', 'Utility');
        $dir = new Folder(self::OBJECTS_DIR, false);
        return $dir->read(true, false, $fullPath)[0];
    }

    private function getFullPathFromTemplateName($templateName)
    {
        return self::OBJECTS_DIR . DS . $templateName . DS . 'definition.json';
    }
}
