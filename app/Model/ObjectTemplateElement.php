<?php

App::uses('AppModel', 'Model');

class ObjectTemplateElement extends AppModel
{
    public $actsAs = array(
            'Containable'
    );

    public $belongsTo = array(
    );

    public $validate = array(
    );

    public function afterFind($results, $primary = false)
    {
        foreach ($results as $k => $result) {
            if (isset($results[$k]['ObjectTemplateElement']['categories'])) {
                $results[$k]['ObjectTemplateElement']['categories'] = json_decode($results[$k]['ObjectTemplateElement']['categories'], true);
            }
            if (isset($results[$k]['ObjectTemplateElement']['values_list'])) {
                $results[$k]['ObjectTemplateElement']['values_list'] = json_decode($results[$k]['ObjectTemplateElement']['values_list'], true);
            }
            if (isset($results[$k]['ObjectTemplateElement']['sane_default'])) {
                $results[$k]['ObjectTemplateElement']['sane_default'] = json_decode($results[$k]['ObjectTemplateElement']['sane_default'], true);
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
            $this->data['ObjectTemplateElement'][$field] = empty($this->data['ObjectTemplateElement'][$field]) ? '[]' : json_encode($this->data['ObjectTemplateElement'][$field]);
        }
        return true;
    }
}
