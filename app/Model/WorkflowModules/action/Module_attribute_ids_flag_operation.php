<?php
include_once APP . 'Model/WorkflowModules/action/Module_attribute_edition_operation.php';

class Module_attribute_ids_flag_operation extends Module_attribute_edition_operation
{
    public $version = '0.1';
    public $blocking = false;
    public $id = 'attribute_ids_flag_operation';
    public $name = 'Attribute IDS Flag operation';
    public $description = 'Toggle or remove the IDS flag on selected attributes.';
    public $icon = 'edit';
    public $inputs = 1;
    public $outputs = 1;
    public $support_filters = true;
    public $expect_misp_core_format = true;
    public $params = [];


    public function __construct()
    {
        parent::__construct();
        $this->params = [
            [
                'id' => 'action',
                'label' => __('To IDS Flag'),
                'type' => 'select',
                'options' => [
                    'add' => __('Toggle IDS flag'),
                    'remove' => __('Remove IDS flag'),
                ],
                'default' => 'add',
            ],
        ];
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors = []): bool
    {
        parent::exec($node, $roamingData, $errors);
        $rData = $roamingData->getData();
        $params = $this->getParamsWithValues($node, $rData);
        $user = $roamingData->getUser();

        $matchingItems = $this->getMatchingItemsForAttributes($node, $rData);
        if ($matchingItems === false) {
            return true;
        }
        $result = $this->__saveAttributes($matchingItems, $rData, $params, $user);
        $success = $result['success'];
        $updatedRData = $result['updated_rData'];
        $roamingData->setData($updatedRData);
        return $success;
    }

    protected function _editAttribute(array $attribute, array $rData, array $params): array
    {
        if ($params['action']['value'] == 'remove') {
            $attribute['to_ids'] = false;
        } else {
            $attribute['to_ids'] = true;
        }
        return $attribute;
    }
}
