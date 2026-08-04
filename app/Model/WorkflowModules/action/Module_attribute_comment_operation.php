<?php
include_once APP . 'Model/WorkflowModules/action/Module_attribute_edition_operation.php';

class Module_attribute_comment_operation extends Module_attribute_edition_operation
{
    public $version = '0.1';
    public $blocking = false;
    public $id = 'Module_attribute_comment_operation';
    public $name = 'Attribute comment operation';
    public $description = 'Set the Attribute\'s comment to the selected value';
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
                'id' => 'comment',
                'label' => __('Comment'),
                'type' => 'textarea',
                'placeholder' => 'Comment to be set',
                'jinja_supported' => true,
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
        $currentRData = $rData;
        $currentRData['__currentAttribute'] = $attribute;
        $renderedComment = $params['comment']['value'];
        if ($attribute['comment'] !== $params['comment']['value']) {
            $attribute['comment'] = $renderedComment;
        }
        return $attribute;
    }
}
