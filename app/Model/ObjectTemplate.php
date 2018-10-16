<?php

App::uses('AppModel', 'Model');

class ObjectTemplate extends AppModel
{
    public $actsAs = array(
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
    public $validate = array(
    );

    public function afterFind($results, $primary = false)
    {
        foreach ($results as $k => $result) {
            if (isset($results[$k]['ObjectTemplate']['requirements'])) {
                $results[$k]['ObjectTemplate']['requirements'] = json_decode($results[$k]['ObjectTemplate']['requirements'], true);
            }
        }
        return $results;
    }

    public function beforeSave($options = array())
    {
        $this->data['ObjectTemplate']['requirements'] = empty($this->data['ObjectTemplate']['requirements']) ? '[]' : json_encode($this->data['ObjectTemplate']['requirements']);
        return true;
    }

    public function update($user, $type = false, $force = false)
    {
        $objectsDir = APP . 'files/misp-objects/objects';
        $directories = glob($objectsDir . '/*', GLOB_ONLYDIR);
        foreach ($directories as $k => $dir) {
            $dir = str_replace($objectsDir, '', $dir);
            $directories[$k] = $dir;
        }
        $updated = array();
        foreach ($directories as $dir) {
            if ($type && '/' . $type != $dir) {
                continue;
            }
            if (!file_exists($objectsDir . DS . $dir . DS . 'definition.json')) {
                continue;
            }
            $file = new File($objectsDir . DS . $dir . DS . 'definition.json');
            $template = json_decode($file->read(), true);
            $file->close();
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

    private function __updateObjectTemplate($template, $current, $user)
    {
        $success = false;
        $template['requirements'] = array();
        $requirementFields = array('required', 'requiredOneOf');
        foreach ($requirementFields as $field) {
            if (isset($template[$field])) {
                $template['requirements'][$field] = $template[$field];
            }
        }
        $template['user_id'] = $user['id'];
        $template['org_id'] = $user['org_id'];
        $template['fixed'] = 1;
        $this->create();
        $result = $this->save($template);
        if (!$result) {
            return $this->validationErrors;
        }
        $id = $this->id;
        $this->setActive($id);
        $fieldsToCompare = array('object_relation', 'type', 'ui-priority', 'categories', 'sane_default', 'values_list', 'multiple', 'disable_correlation');
        foreach ($template['attributes'] as $k => $attribute) {
            $attribute['object_relation'] = $k;
            $attribute = $this->__convertJSONToElement($attribute);
            $this->ObjectTemplateElement->create();
            $attribute['object_template_id'] = $id;
            $result = $this->ObjectTemplateElement->save(array('ObjectTemplateElement' => $attribute));
        }
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

    // simple test to see if there are any object templates - if not trigger update
    public function populateIfEmpty($user)
    {
        $result = $this->find('first', array(
            'recursive' => -1,
            'fields' => array('ObjectTemplate.id')
        ));
        if (empty($result)) {
            $this->update($user);
        }
        return true;
    }

    public function setActive($id)
    {
        $template = $this->find('first', array(
            'recursive' => -1,
            'conditions' => array('ObjectTemplate.id' => $id)
        ));
        if (empty($template)) {
            return false;
        }
        if ($template['ObjectTemplate']['active']) {
            $template['ObjectTemplate']['active'] = 0;
            $this->save($template);
            return 0;
        }
        $similar_templates = $this->find('all', array(
            'recursive' => -1,
            'conditions' => array(
                'ObjectTemplate.uuid' => $template['ObjectTemplate']['uuid'],
                'NOT' => array(
                    'ObjectTemplate.id' => $template['ObjectTemplate']['id']
                )
            )
        ));
        $template['ObjectTemplate']['active'] = 1;
        $this->save($template);
        foreach ($similar_templates as $st) {
            $st['ObjectTemplate']['active'] = 0;
            $this->save($st);
        }
        return 1;
    }
}
