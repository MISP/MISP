<?php

class MispAdminSyncTestWidget
{
    public $title = 'MISP Sync Test';
    public $category = 'system';
    public $render = 'NetworkGraph';
    public $width = 4;
    public $height = 5;
    public $params = array();
    public $schema = array();
    public $description = 'Network diagram of the sync servers this instance connects to, each node coloured by its live connection-test outcome (hover a node for the URL + reason).';
    public $cacheLifetime = 1;
    // Connection tests hit every sync server over the network on each
    // render, so do NOT let the board scheduler re-run them on a timer —
    // the admin refreshes manually when they want a fresh probe.
    public $autoRefreshDelay = false;

    public function handler($user, $options = array())
    {
        $this->Server = ClassRegistry::init('Server');
        $servers = $this->Server->find('all', array(
            'fields' => array('id', 'url', 'name', 'pull', 'push', 'caching_enabled', 'authkey', 'cert_file', 'client_cert_file', 'self_signed', 'skip_proxy'),
            'conditions' => array('OR' => array('pull' => 1, 'push' => 1, 'caching_enabled' => 1)),
            'recursive' => -1
        ));
        if (empty($servers)) {
            return array('error' => __('No sync servers configured.'));
        }

        // The current instance is the hub node.
        $baseurl = Configure::read('MISP.baseurl');
        $selfName = Configure::read('MISP.org');
        $nodes = array(array(
            'id' => 'self',
            'name' => !empty($selfName) ? $selfName : __('This instance'),
            'url' => !empty($baseurl) ? $baseurl : '',
            'status' => 'self',
            'message' => __('Current instance (sync root).'),
        ));
        $links = array();

        $syncTestErrorCodes = $this->Server->syncTestErrorCodes;
        foreach ($servers as $server) {
            $result = $this->Server->runConnectionTest($server, false);
            if ($result['status'] === 1) {
                // Connected — green unless an access permission is missing,
                // in which case amber with the specific gap spelled out.
                $status = 'ok';
                $message = __('Connected.');
                if (empty($result['info']['perm_sync'])) {
                    $status = 'warn';
                    $message .= ' ' . __('No sync access.');
                }
                if (empty($result['info']['perm_sighting'])) {
                    $status = 'warn';
                    $message .= ' ' . __('No sighting access.');
                }
                if (empty($result['info']['perm_analyst_data'])) {
                    $status = 'warn';
                    $message .= ' ' . __('No analyst data sync access.');
                }
            } else {
                $status = 'error';
                $message = $syncTestErrorCodes[$result['status']];
            }
            $id = 'srv-' . $server['Server']['id'];
            $nodes[] = array(
                'id' => $id,
                'name' => sprintf(
                    '#%s %s',
                    $server['Server']['id'],
                    $server['Server']['name']
                ),
                'url' => $server['Server']['url'],
                'status' => $status,
                'message' => $message,
            );
            $links[] = array('source' => 'self', 'target' => $id);
        }

        return array('nodes' => $nodes, 'links' => $links);
    }

    public function checkPermissions($user)
    {
        if (empty($user['Role']['perm_site_admin'])) {
            return false;
        }
        return true;
    }
}
