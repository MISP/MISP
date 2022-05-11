<?php
App::uses('BackgroundJobsTool', 'Tools');
require_once 'AppShell.php';

/**
 * @property Job $Job
 * @property User $User
 */
class ModuleShell extends AppShell
{
    public $uses = array('Module', 'User', 'Job', 'Server');

    public function execute_action_module()
    {
        if (!isset($this->args[0]) || empty($this->args[1]) || empty($this->args[2])) {
            die('Usage: ' . $this->Server->command_line_functions['console_automation_tasks']['data']['Execute Action Module'] . PHP_EOL);
        }

        $userId = $this->args[0];
        $data = $this->args[1];
        if (!empty($this->args[2])) {
            $jobId = $this->args[2];
        } else {
            $jobId = $this->Job->createJob(null, Job::WORKER_PRIO, 'execute_action_module', 'Module: ' . $data["module"], 'Executing...');
        }
        $this->Job->read(null, $jobId);
        $result = $this->Module->executeAction($data);
        if (empty($result['data']) || !empty($result['error'])) {
            $message = empty($result['error']) ? __('Execution failed for module %s.', $data['module']) : $result['error'];
            $this->Job->saveStatus($jobId, false, $message);
        } else {
            $message = 'Job done.';
            $this->Job->saveStatus($jobId, true, $message);
            $this->Job->saveProgress($jobId, $message, 100);
        }
    }

    /**
     * @param int $userId
     * @return array
     */
    private function getUser($userId)
    {
        $user = $this->User->getAuthUser($userId);
        if (empty($user)) {
            $this->error('User ID do not match an existing user.');
        }
        return $user;
    }

}
