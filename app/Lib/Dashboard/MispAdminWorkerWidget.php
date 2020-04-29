<?php

class MispAdminWorkerWidget
{
    public $title = 'MISP Workers';
    public $render = 'SimpleList';
    public $width = 2;
    public $height = 2;
    public $params = array();
    public $description = 'Basic widget showing some server statistics in regards to MISP.';
    public $cacheLifetime = false;
    public $autoRefreshDelay = 5;


	public function handler($user, $options = array())
	{
        $this->Server = ClassRegistry::init('Server');
        $workerIssueCount = array();
        $results = $this->Server->workerDiagnostics($workerIssueCount);
        $data = array();
        foreach ($results as $queueName => $queue) {
            if (in_array($queueName, array('controls', 'proc_accessible'))) {
                continue;
            }
            $total = 0;
            $alive = 0;
            if (!empty($queue['workers'])) {
                foreach ($queue['workers'] as $worker) {
                    if ($worker['alive']) {
                        $alive += 1;
                    }
                    $total += 1;
                }
            }
            $colour = 'green';
            if ($alive == 0) {
                $colour = 'red';
            } else {
                if ($alive != $total) {
                    $colour = 'orange';
                }
            }
            $data[] = array(
                'title' => h($queueName) . ' workers alive',
                'value' => sprintf('[%s/%s]', $alive, $total),
                'class' => $colour
            );
            $data[] = array(
                'title' => h($queueName) . ' jobs pending',
                'value' => empty($queue['jobCount']) ? '0' : h($queue['jobCount'])
            );
            $data[] = array(
                'type' => 'gap'
            );
        }
        return $data;
	}

    public function checkPermissions($user)
    {
        if (empty($user['Role']['perm_site_admin'])) {
            return false;
        }
        return true;
    }
}
