<?php

namespace App\Model\Entity;

use App\Model\Entity\AppModel;

class MetaTemplateField extends AppModel
{
    protected $_virtual = ['index_type', 'form_type', 'form_options', ];

    protected function _getIndexType()
    {
        $indexType = 'text';
        if ($this->type === 'boolean') {
            $indexType = 'boolean';
        } else if ($this->type === 'date') {
            $indexType = 'datetime';
        } else if ($this->type === 'ipv4' || $this->type === 'ipv6') {
            $indexType = 'text';
        }
        return $indexType;
    }

    protected function _getFormType()
    {
        $formType = 'text';
        if (!empty($this->sane_default) || !empty($this->values_list)) {
            $formType = 'dropdown';
        } else if ($this->type === 'boolean') {
            $formType = 'checkbox';
        }
        return $formType;
    }

    protected function _getFormOptions()
    {
        $formOptions = [];
        if ($this->formType === 'dropdown') {
            $selectOptions = !empty($this->sane_default) ? $this->sane_default : $this->values_list;
            $selectOptions = array_combine($selectOptions, $selectOptions);
            if (!empty($this->sane_default)) {
                $selectOptions[] = ['value' => '_custom', 'text' => __('-- custom value --'), 'class' => 'custom-value'];
            }
            $selectOptions[''] = __('-- no value --');
            $formOptions['options'] = $selectOptions;
        }
        return $formOptions;
    }

}
