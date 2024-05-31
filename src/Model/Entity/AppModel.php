<?php

namespace App\Model\Entity;

use Cake\Core\Configure;
use Cake\ORM\Entity;
use Cake\ORM\Locator\LocatorAwareTrait;

class AppModel extends Entity
{
    use LocatorAwareTrait;

    const BROTLI_HEADER = "\xce\xb2\xcf\x81";
    const BROTLI_MIN_LENGTH = 200;

    public const ACTION_ADD = 'add',
        ACTION_EDIT = 'edit',
        ACTION_SOFT_DELETE = 'soft_delete',
        ACTION_DELETE = 'delete',
        ACTION_UNDELETE = 'undelete',
        ACTION_TAG = 'tag',
        ACTION_TAG_LOCAL = 'tag_local',
        ACTION_REMOVE_TAG = 'remove_tag',
        ACTION_REMOVE_TAG_LOCAL = 'remove_local_tag',
        ACTION_LOGIN = 'login',
        ACTION_LOGIN_FAIL = 'login_fail',
        ACTION_LOGOUT = 'logout';


    /** @var WorkflowsTable $Workflow  */
    private $Workflow;

    public function getConstant($name)
    {
        return constant('self::' . $name);
    }

    public function getAccessibleFieldForNew(): array
    {
        return $this->_accessibleOnNew ?? [];
    }

    public function rearrangeForAPI(): void
    {
    }

    public function rearrangeMetaFields(): void
    {
        $this->meta_fields = [];
        foreach ($this->MetaTemplates as $template) {
            foreach ($template['meta_template_fields'] as $field) {
                if ($field['counter'] > 0) {
                    foreach ($field['metaFields'] as $metaField) {
                        if (!empty($this->meta_fields[$template['name']][$field['field']])) {
                            if (!is_array($this->meta_fields[$template['name']][$field['field']])) {
                                $this->meta_fields[$template['name']][$field['field']] = [$this->meta_fields[$template['name']][$field['field']]];
                            }
                            $this->meta_fields[$template['name']][$field['field']][] = $metaField['value'];
                        } else {
                            $this->meta_fields[$template['name']][$field['field']] = $metaField['value'];
                        }
                    }
                }
            }
        }
    }

    public function rearrangeTags(array $tags): array
    {
        foreach ($tags as &$tag) {
            $tag = [
                'id' => $tag['id'],
                'name' => $tag['name'],
                'colour' => $tag['colour']
            ];
        }
        return $tags;
    }

    public function rearrangeAlignments(array $alignments): array
    {
        $rearrangedAlignments = [];
        $validAlignmentTypes = ['individual', 'organisation'];
        $alignmentDataToKeep = [
            'individual' => [
                'id',
                'email'
            ],
            'organisation' => [
                'id',
                'uuid',
                'name'
            ]
        ];
        foreach ($alignments as $alignment) {
            foreach (array_keys($alignmentDataToKeep) as $type) {
                if (isset($alignment[$type])) {
                    $alignment[$type]['type'] = $alignment['type'];
                    $temp = [];
                    foreach ($alignmentDataToKeep[$type] as $field) {
                        $temp[$field] = $alignment[$type][$field];
                    }
                    $rearrangedAlignments[$type][] = $temp;
                }
            }
        }
        return $rearrangedAlignments;
    }

    public function rearrangeSimplify(array $typesToRearrange): void
    {
        if (in_array('organisation', $typesToRearrange) && isset($this->organisation)) {
            $this->organisation = [
                'id' => $this->organisation['id'],
                'name' => $this->organisation['name'],
                'uuid' => $this->organisation['uuid']
            ];
        }
        if (in_array('individual', $typesToRearrange) && isset($this->individual)) {
            $this->individual = [
                'id' => $this->individual['id'],
                'email' => $this->individual['email'],
                'uuid' => $this->individual['uuid']
            ];
        }
    }

    /**
     * executeTrigger
     *
     * @param string $trigger_id
     * @param array $data Data to be passed to the workflow
     * @param array $blockingErrors Errors will be appened if any
     * @param array $logging If the execution failure should be logged
     * @return boolean If the execution for the blocking path was a success
     */
    protected function executeTrigger($trigger_id, array $data = [], array &$blockingErrors = [], array $logging = []): bool
    {
        if ($this->isTriggerCallable($trigger_id)) {
            $success = $this->Workflow->executeWorkflowForTriggerRouter($trigger_id, $data, $blockingErrors, $logging);
            if (!empty($logging) && empty($success)) {
                $logging['message'] = !empty($logging['message']) ? $logging['message'] : __('Error while executing workflow.');
                $errorMessage = implode(', ', $blockingErrors);
                $LogsTable = $this->fetchTable('Logs');
                $LogsTable->createLogEntry('SYSTEM', $logging['action'], $logging['model'], $logging['id'], $logging['message'], __('Returned message: %s', $errorMessage));
            }
            return $success;
        }
        return true;
    }

    protected function isTriggerCallable($trigger_id): bool
    {
        static $workflowEnabled;
        if ($workflowEnabled === null) {
            $workflowEnabled = (bool)Configure::read('Plugin.Workflow_enable');
        }

        if (!$workflowEnabled) {
            return false;
        }

        if ($this->Workflow === null) {
            $this->Workflow = $this->fetchTable('Workflows');
        }
        return $this->Workflow->checkTriggerEnabled($trigger_id) &&
            $this->Workflow->checkTriggerListenedTo($trigger_id);
    }
}
