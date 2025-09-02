<?php
declare(strict_types=1);

require_once 'AppShell.php';

class WorkflowShell extends AppShell {

    public $uses = ['Job', 'Workflow'];

    public function executeWorkflowForTrigger()
    {
        if (empty($this->args[0]) || empty($this->args[1]) || empty($this->args[2]) || empty($this->args[3])) {
            die(__('Invalid number of arguments.'));
        }

        $trigger_id = $this->args[0];
        $data = JsonTool::decode($this->args[1]);
        $logging = JsonTool::decode($this->args[2]);
        $jobId = $this->args[3];
        if (!empty($this->args[4])) {
            Configure::write('CurrentUserId', JsonTool::decode($this->args[4]));
        }
        $initiator_user_id = Configure::check('CurrentUserId') ? Configure::read('CurrentUserId') : null;
        Configure::write('InitiatorUserId', $initiator_user_id);

        $blockingErrors = [];
        $executionSuccess = $this->Workflow->executeWorkflowForTrigger($trigger_id, $data, $blockingErrors);

        $job = $this->Job->read(null, $jobId);
        $job['Job']['progress'] = 100;
        $job['Job']['status'] = Job::STATUS_COMPLETED;
        $job['Job']['date_modified'] = date("Y-m-d H:i:s");
        if ($executionSuccess) {
            $job['Job']['message'] = __('Workflow for trigger `%s` completed execution', $trigger_id);
        } else {
            $errorMessage = implode(', ', $blockingErrors);
            $message = __('Error while executing workflow for trigger `%s`: %s. %s%s', $trigger_id, $logging['message'], PHP_EOL, __('Returned message: %s', $errorMessage));
            $job['Job']['message'] = $message;
        }
    }

    public function executeAdHocWorkflow()
    {
        if (empty($this->args[0])) {
            die(__('Invalid number of arguments.'));
        }

        $workflow_id = $this->args[0];
        $workflow_payload = !empty($this->args[1]) ? JsonTool::decode($this->args[1]) : [];
        $jobId = !empty($this->args[3]) ? $this->args[3] : null;

        if (!$this->Workflow->isAdHocWorkflow($workflow_id)) {
            throw new MethodNotAllowedException("Can only run a Ad-Hoc Workflow");
        }

        $logging = [
            'model' => 'Workflow',
            'action' => 'adhoc',
            'id' => $workflow_id,
            'message' => 'Ad-Hoc Workflow execution stopped.',
        ];
        $blockingErrors = [];
        $executionSuccess = $this->Workflow->executeWorkflow($workflow_id, $workflow_payload, $blockingErrors);

        $successMessage = __('Workflow `%s` completed execution', $workflow_id);
        $errorMessageConcat = implode(', ', $blockingErrors);
        $errorMessage = __('Error while executing workflow `%s`: %s. %s', $workflow_id, $logging['message'], PHP_EOL . __('Returned message: %s', $errorMessageConcat));
        if (!is_null($jobId)) {
            $job = $this->Job->read(null, $jobId);
            $job['Job']['progress'] = 100;
            $job['Job']['status'] = Job::STATUS_COMPLETED;
            $job['Job']['date_modified'] = date("Y-m-d H:i:s");
            $job['Job']['message'] = $executionSuccess ? $successMessage : $errorMessage;
            $this->Job->save($job);
        } else {
            echo ($executionSuccess ? $successMessage : $errorMessage) . PHP_EOL;
        }
    }

    public function walkGraph()
    {
        if (empty($this->args[0]) || empty($this->args[1]) || empty($this->args[2]) || empty($this->args[3])) {
            die(__('Invalid number of arguments.'));
        }

        $workflow_id = (int)$this->args[0];
        $workflow = $this->Workflow->fetchWorkflow($workflow_id);
        $node_id_to_exec = (int)$this->args[1];
        $roamingData = JsonTool::decode($this->args[2]);
        $for_path = $this->args[3];
        $jobId = $this->args[4];

        $concurrentErrors = [];
        $walkResult = [];
        $executionSuccess = $this->Workflow->walkGraph(
            $workflow,
            $node_id_to_exec,
            $for_path,
            $roamingData,
            $concurrentErrors,
            $walkResult
        );
        $job = $this->Job->read(null, $jobId);
        $job['Job']['progress'] = 100;
        $job['Job']['status'] = Job::STATUS_COMPLETED;
        $job['Job']['date_modified'] = date("Y-m-d H:i:s");
        if ($executionSuccess) {
            $job['Job']['message'] = __('Workflow concurrent task executed %s nodes starting from node %s.', count($walkResult['executed_nodes']), $node_id_to_exec);
        } else {
            $message = __('Error while executing workflow concurrent task. %s', PHP_EOL . implode(', ', $concurrentErrors));
            $this->Workflow->logExecutionError($workflow, $message);
            $job['Job']['message'] = $message;
        }
        $this->Job->save($job);
    }
}
