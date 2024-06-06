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
            $message = __('Error while executing workflow for trigger `%s`: %s. %s%s', $trigger_id, $logging['message'], PHP_EOL . __('Returned message: %s', $errorMessage));
            $job['Job']['message'] = $message;
        }
        $this->Job->save($job);
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
