<?php
App::uses('AppModel', 'Model');

class ObjectTemplateElement extends AppModel
{
    public $actsAs = array(
        'Containable'
    );

    public function afterFind($results, $primary = false)
    {
        foreach ($results as &$result) {
            if (isset($result['ObjectTemplateElement']['categories'])) {
                $result['ObjectTemplateElement']['categories'] = JsonTool::decode($result['ObjectTemplateElement']['categories']);
            }
            if (isset($result['ObjectTemplateElement']['values_list'])) {
                $result['ObjectTemplateElement']['values_list'] = JsonTool::decode($result['ObjectTemplateElement']['values_list']);
            }
            if (isset($result['ObjectTemplateElement']['sane_default'])) {
                $result['ObjectTemplateElement']['sane_default'] = JsonTool::decode($result['ObjectTemplateElement']['sane_default']);
            }
        }
        return $results;
    }

    public function beforeSave($options = array())
    {
        if (empty($this->data['ObjectTemplateElement']['description'])) {
            $this->data['ObjectTemplateElement']['description'] = '';
        }
        $json_fields = array('categories', 'values_list', 'sane_default');
        foreach ($json_fields as $field) {
            $this->data['ObjectTemplateElement'][$field] = empty($this->data['ObjectTemplateElement'][$field]) ? '[]' : JsonTool::encode($this->data['ObjectTemplateElement'][$field]);
        }
        return true;
    }

    public function getAllAvailableTypes()
    {
        $temp = $this->find('all', array(
            'recursive' => -1,
            'fields' => array('object_relation as type', 'description AS desc', 'categories'),
            'group' => array('object_relation', 'description', 'categories')
        ));
        $res = array();
        foreach ($temp as $type) {
            $res[$type['ObjectTemplateElement']['type']] = array(
                'desc' => $type['ObjectTemplateElement']['desc'],
                'category' => $type['ObjectTemplateElement']['categories']
            );
        }
        return $res;
    }
}
