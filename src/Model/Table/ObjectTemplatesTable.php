<?php

namespace App\Model\Table;

use App\Lib\Tools\FileAccessTool;
use App\Model\Table\AppTable;
use Cake\Validation\Validation;
use DirectoryIterator;

class ObjectTemplatesTable extends AppTable
{
    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->addBehavior('UUID');
        $this->addBehavior('AuditLog');
        $this->addBehavior(
            'JsonFields',
            [
            'fields' => ['requirements'],
            ]
        );
        $this->belongsTo(
            'Users',
            [
                'foreignKey' => 'user_id',
                'propertyName' => 'User',
                ]
        );
            $this->belongsTo(
                'Organisations',
                [
                    'foreignKey' => 'org_id',
                    'propertyName' => 'Organisation',
                ]
            );
        $this->hasMany(
            'ObjectTemplateElements',
            [
                'propertyName' => 'ObjectTemplateElement',
                'dependent' => false,
                'cascadeCallbacks' => false
            ]
        );
        $this->setDisplayField('name');
    }

    const OBJECTS_DIR = APP . '../libraries/misp-objects/objects';

    public function update($user = false, $type = false, $force = false)
    {
        $directories = $this->getTemplateDirectoryPaths();
        $updated = [];
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
            $template['meta_category'] = $template['meta-category'] ?? '';
            $current = $this->find(
                'all',
                [
                'fields' => ['version' => 'MAX(version)', 'uuid'],
                'conditions' => ['uuid' => $template['uuid']],
                'recursive' => -1,
                'group' => ['uuid']
                ]
            )->first();
            if (!empty($current)) {
                $current['version'] = $current['version'];
            }
            if ($force || empty($current) || $template['version'] > $current['version']) {
                $result = $this->__updateObjectTemplate($template, $current, $user);
                if ($result === true) {
                    $temp = ['name' => $template['name'], 'new' => $template['version']];
                    if (!empty($current)) {
                        $temp['old'] = $current['version'];
                    }
                    $updated['success'][] = $temp;
                } else {
                    $updated['fails'][] = ['name' => $template['name'], 'fail' => json_encode($result)];
                }
            }
        }
        return $updated;
    }

    private function __updateObjectTemplate($template, $current, $user = false)
    {
        $template['requirements'] = [];
        $requirementFields = ['required', 'requiredOneOf'];
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
        $templateEntity = $this->newEntity($template);
        $templateEntity->requirements = $template['requirements'];
        $result = $this->save($templateEntity);
        if (!$result) {
            return $this->validationErrors;
        }
        $id = $templateEntity->id;
        $this->setActive($id);

        $attributes = [];
        foreach ($template['attributes'] as $k => $attribute) {
            $attribute = $this->__convertJSONToElement($attribute);
            $attribute['object_relation'] = $k;
            $attribute['object_template_id'] = $id;
            $attributeEntity = $this->ObjectTemplateElements->newEntity($attribute);
            $attributeEntity->categories = $attribute['categories'] ?? [];
            $attributeEntity->values_list = $attribute['values_list'] ?? [];
            $attributeEntity->sane_default = $attribute['sane_default'] ?? [];

            $attributes[] = $attributeEntity;
        }
        $this->ObjectTemplateElements->saveMany($attributes);

        return true;
    }

    private function __convertJSONToElement($attribute)
    {
        $result = [];
        $translation_table = [
            'misp-usage-frequency' => 'frequency',
            'misp-attribute' => 'type',
            'description' => 'description',
            'ui-priority' => 'ui_priority',
            'type' => 'type',
            'disable_correlation' => 'disable_correlation',
            'object_relation' => 'object_relation',
            'categories' => 'categories',
            'sane_default' => 'sane_default',
            'values_list' => 'values_list',
            'multiple' => 'multiple'
        ];
        foreach ($translation_table as $from => $to) {
            if (isset($attribute[$from])) {
                $result[$to] = $attribute[$from];
            }
        }
        return $result;
    }

    public function checkTemplateConformity($template, $attributes)
    {
        if (!empty($template['requirements'])) {
            // check for all required attributes
            if (!empty($template['requirements']['required'])) {
                foreach ($template['requirements']['required'] as $requiredField) {
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
            if (!empty($template['requirements']['requiredOneOf'])) {
                $found = false;
                foreach ($template['requirements']['requiredOneOf'] as $requiredField) {
                    foreach ($attributes['Attribute'] as $attribute) {
                        if ($attribute['object_relation'] == $requiredField) {
                            $found = true;
                        }
                    }
                }
                if (!$found) {
                    return 'Could not save the object as it requires at least one of the following attributes to be set: ' . implode(', ', $template['requirements']['requiredOneOf']);
                }
            }
        }
        // check the multiple flag is adhered to
        foreach ($template['ObjectTemplateElement'] as $template_attribute) {
            if ($template_attribute['multiple'] !== true) {
                $found_relations = [];
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
        $potentialTemplateIds = $this->find(
            'column',
            [
            'recursive' => -1,
            'fields' => [
                'ObjectTemplate.id',
            ],
            'conditions' => [
                'ObjectTemplate.active' => true,
                'ObjectTemplateElements.type' => $uniqueAttributeTypes,
            ],
            'joins' => [
                [
                    'table' => 'object_template_elements',
                    'alias' => 'ObjectTemplateElements',
                    'type' => 'RIGHT',
                    'fields' => ['ObjectTemplateElements.object_relation', 'ObjectTemplateElements.type'],
                    'conditions' => ['ObjectTemplate.id = ObjectTemplateElements.object_template_id']
                ]
            ],
            'group' => 'ObjectTemplate.id',
            ]
        );

        $templates = $this->find(
            'all',
            [
            'recursive' => -1,
            'conditions' => ['id' => $potentialTemplateIds],
            'contain' => ['ObjectTemplateElements' => ['fields' => ['object_relation', 'type', 'multiple']]]
            ]
        );

        foreach ($templates as $i => $template) {
            $res = $this->checkTemplateConformityBasedOnTypes($template, $attributeTypes);
            $templates[$i]['compatibility'] = $res['valid'] ? true : $res['missingTypes'];
            $templates[$i]['invalidTypes'] = $res['invalidTypes'];
            $templates[$i]['invalidTypesMultiple'] = $res['invalidTypesMultiple'];
        }

        usort(
            $templates->toArray(),
            function ($a, $b) {
            if ($a['id'] == $b['id']) {
                return 0;
            } else if (is_array($a['compatibility']) && is_array($b['compatibility'])) {
                return count($a['compatibility']) > count($b['compatibility']) ? 1 : -1;
            } else if (is_array($a['compatibility']) && !is_array($b['compatibility'])) {
                return 1;
            } else if (!is_array($a['compatibility']) && is_array($b['compatibility'])) {
                return -1;
            } else { // sort based on invalidTypes count
                return count($a['invalidTypes']) > count($b['invalidTypes']) ? 1 : -1;
            }
            }
        );

        return ['templates' => $templates, 'types' => $uniqueAttributeTypes];
    }

    /**
     * @param array $template
     * @param array $attributeTypes Array of attribute types to check, can contains multiple types
     * @return array
     */
    public function checkTemplateConformityBasedOnTypes(array $template, array $attributeTypes)
    {
        $to_return = ['valid' => true, 'missingTypes' => []];
        if (!empty($template['requirements'])) {
            // construct array containing ObjectTemplateElement with object_relation as key for faster search
            $elementsByObjectRelationName = array_column($template['ObjectTemplateElement'], null, 'object_relation');

            // check for all required attributes
            if (!empty($template['requirements']['required'])) {
                foreach ($template['requirements']['required'] as $requiredField) {
                    $requiredType = $elementsByObjectRelationName[$requiredField]['type'];
                    $found = in_array($requiredType, $attributeTypes, true);
                    if (!$found) {
                        $to_return = ['valid' => false, 'missingTypes' => [$requiredType]];
                    }
                }
            }
            // check for all required one of attributes
            if (!empty($template['requirements']['requiredOneOf'])) {
                $found = false;
                $allRequiredTypes = [];
                foreach ($template['requirements']['requiredOneOf'] as $requiredField) {
                    $requiredType = $elementsByObjectRelationName[$requiredField]['type'] ?? null;
                    $allRequiredTypes[] = $requiredType;
                    if (!$found) {
                        $found = in_array($requiredType, $attributeTypes, true);
                    }
                }
                if (!$found) {
                    $to_return = ['valid' => false, 'missingTypes' => $allRequiredTypes];
                }
            }
        }

        // at this point, an object could created; checking if all attribute are valid
        $valid_types = [];
        $to_return['invalidTypes'] = [];
        $to_return['invalidTypesMultiple'] = [];
        foreach ($template['ObjectTemplateElement'] as $templateElement) {
            $valid_types[$templateElement['type']] = $templateElement['multiple'];
        }
        $check_for_multiple_type = [];
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
        $template = $this->find(
            'all',
            [
            'recursive' => -1,
            'conditions' => ['ObjectTemplates.id' => $id],
            'fields' => ['ObjectTemplates.id', 'ObjectTemplates.uuid', 'ObjectTemplates.active'],
            ]
        )->first();
        if (empty($template)) {
            return false;
        }
        if ($template['active']) {
            $template['active'] = 0;
            $this->save($template, true, ['active']);
            return 0;
        }
        $similar_templates = $this->find(
            'all',
            [
            'recursive' => -1,
            'fields' => ['ObjectTemplates.id'],
            'conditions' => [
                'ObjectTemplates.uuid' => $template['uuid'],
                'NOT' => [
                    'ObjectTemplates.id' => $template['id']
                ]
            ]
            ]
        );
        $template['active'] = 1;
        $this->save($template, true, ['active']);
        foreach ($similar_templates as $st) {
            $st['active'] = 0;
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
            $allTemplateNames = $this->getTemplateDirectoryPaths();
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
     * @return array
     */
    private function getTemplateDirectoryPaths()
    {
        $dir = new DirectoryIterator(self::OBJECTS_DIR);

        $templates = [];
        foreach ($dir as $fileinfo) {
            if ($fileinfo->isDir() && !$fileinfo->isDot()) {
                $templates[] = $fileinfo->getFilename();
            }
        }

        return $templates;
    }

    private function getFullPathFromTemplateName($templateName)
    {
        return self::OBJECTS_DIR . DS . $templateName . DS . 'definition.json';
    }
}
