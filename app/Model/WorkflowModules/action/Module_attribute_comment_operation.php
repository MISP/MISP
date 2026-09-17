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
        // Keep the raw (un-rendered) comment template so _editAttribute can
        // re-render it per attribute when it references the attribute (#10898).
        $indexedParams = $node['data']['indexed_params'] ?? [];
        $params['comment']['template'] = $indexedParams['comment'] ?? '';
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
        $renderedComment = $params['comment']['value'];
        $template = $params['comment']['template'] ?? '';
        // Render once per attribute only when the template reaches into the
        // attribute being edited, so per-attribute values resolve instead of
        // the event-level render being copied onto every match (#10898).
        // Templates that do not reference the attribute keep a single render.
        if (str_contains($template, '__currentAttribute')) {
            $currentRData = $rData;
            $currentRData['__currentAttribute'] = $attribute;
            $currentRData['_env']['baseurl'] = Configure::read('MISP.baseurl');
            $renderedComment = $this->render_jinja_template(
                $template,
                $currentRData
            );
        }
        if ($attribute['comment'] !== $renderedComment) {
            $attribute['comment'] = $renderedComment;
        }
        return $attribute;
    }
}
