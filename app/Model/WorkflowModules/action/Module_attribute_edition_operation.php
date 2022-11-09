<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_attribute_edition_operation extends WorkflowBaseActionModule
{
    public $version = '0.1';
    public $blocking = false;
    public $id = 'attribute_edition_operation';
    public $name = 'Attribute edition operation';
    public $description = 'Base module allowing to modify attribute';
    public $icon = 'edit';
    public $inputs = 1;
    public $outputs = 1;
    public $support_filters = true;
    public $expect_misp_core_format = true;
    public $params = [];

    private $Attribute;


    public function __construct()
    {
        parent::__construct();
        $this->Attribute = ClassRegistry::init('Attribute');
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors = []): bool
    {
        parent::exec($node, $roamingData, $errors);
        $result = true;
        return $result;
    }

    protected function _editAttribute(array $attribute, array $rData, array $params): array
    {
        return $attribute;
    }

    protected function __saveAttribute(array $attributes, array $rData, array $params, array $user): bool
    {
        $success = false;
        foreach ($attributes as $attribute) {
            $attribute = $this->_editAttribute($attribute, $rData, $params);
            unset($attribute['timestamp']);
            $saveSuccess = $this->Attribute->editAttribute($attribute, $rData, $user, $attribute['object_id']);
            $success = $success || !empty($saveSuccess);
        }
        return $success;
    }
}
