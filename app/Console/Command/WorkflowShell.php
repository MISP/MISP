<?php
declare(strict_types=1);

require_once 'AppShell.php';

class WorkflowShell extends AppShell {

    public $uses = ['Job', 'Workflow'];
    public $tasks = ['ConfigLoad'];

    public function walkGraph()
    {
        $this->ConfigLoad->execute();
        if (empty($this->args[0]) || empty($this->args[1]) || empty($this->args[2]) || empty($this->args[3])) {
            die(__('Invalid number of arguments.'));
        }

        $workflow_id = (int)$this->args[0];
        $workflow = $this->Workflow->fetchWorkflow($workflow_id);
        $node_id_to_exec = (int)$this->args[1];
        $roamingData = JsonTool::decode($this->args[2]);
        $jobId = $this->args[3];

        $parallelErrors = [];
        $walkResult = [];
        $executionSuccess = $this->Workflow->walkGraph(
            $workflow,
            $node_id_to_exec,
            null,
            $roamingData,
            $parallelErrors,
            $walkResult,
        );
        $job = $this->Job->read(null, $jobId);
        $job['Job']['progress'] = 100;
        $job['Job']['status'] = Job::STATUS_COMPLETED;
        $job['Job']['date_modified'] = date("Y-m-d H:i:s");
        if ($executionSuccess) {
            $job['Job']['message'] = __('Workflow parallel task executed %s nodes starting from node %s.', count($walkResult['executed_nodes']), $node_id_to_exec);
        } else {
            $job['Job']['message'] = __('Error while executing workflow parallel task. %s', PHP_EOL . implode(', ', $parallelErrors));
        }
        $this->Job->save($job);
    }
}
