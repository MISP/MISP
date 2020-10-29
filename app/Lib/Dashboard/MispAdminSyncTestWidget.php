<?php

class MispAdminSyncTestWidget
{
    public $title = 'MISP Sync Test';
    public $render = 'SimpleList';
    public $width = 3;
    public $height = 2;
    public $params = array();
    public $description = 'Basic widget showing some server statistics in regards to MISP.';
    public $cacheLifetime = 1;


	public function handler($user, $options = array())
	{
        $this->Server = ClassRegistry::init('Server');
        $servers = $this->Server->find('all', array(
            'fields' => array('id', 'url', 'name', 'pull', 'push', 'caching_enabled', 'authkey', 'cert_file', 'client_cert_file', 'self_signed'),
            'conditions' => array('OR' => array('pull' => 1, 'push' => 1, 'caching_enabled' => 1)),
            'recursive' => -1
        ));
        $data = array();
        if (empty($servers)) {
            return array();
        }
        $syncTestErrorCodes = $this->Server->syncTestErrorCodes;
        foreach ($servers as $server) {
            $result = $this->Server->runConnectionTest($server);
            if ($result['status'] === 1) {
                $message = __('Connected.');
                $colour = 'green';
                if (empty($result['info']['perm_sync'])) {
                    $colour = 'orange';
                    $message .= ' ' . __('No sync access.');
                }
                if (empty($result['info']['perm_sighting'])) {
                    $colour = 'orange';
                    $message .= ' ' . __('No sighting access.');
                }
            } else {
                $colour = 'red';
                $message = $syncTestErrorCodes[$result['status']];
            }
            $data[] = array(
                'title' => sprintf(
                    'Server #%s (%s - %s)',
                    h($server['Server']['id']),
                    h($server['Server']['name']),
                    h($server['Server']['url'])
                ),
                'value' => h($message),
                'class' => $colour
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
