<?php

class WhoamiWidget
{
    public $title = 'Whoami';
    public $render = 'SimpleList';
    public $width = 2;
    public $height = 2;
    public $params = array();
    public $description = 'Shows information about the currently logged in user.';
    public $cacheLifetime = false;
    public $autoRefreshDelay = 3;

	public function handler($user, $options = array())
	{
        $this->Log = ClassRegistry::init('Log');
        $entries = $this->Log->find('all', array(
            'recursive' => -1,
            'conditions' => array('action' => 'login', 'user_id' => $user['id']),
            'order' => 'id desc',
            'limit' => 5,
            'fields' => array('created', 'ip')
        ));
        foreach ($entries as &$entry) {
            $entry = $entry['Log']['created'] . ' --- ' . (empty($entry['Log']['ip']) ? 'IP not logged' : $entry['Log']['ip']);
        }
        return array(
            array('title' => 'Email', 'value' => $user['email']),
            array('title' => 'Role', 'value' => $user['Role']['name']),
            array('title' => 'Organisation', 'value' => $user['Organisation']['name']),
            array('title' => 'IP', 'value' => empty($_SERVER['HTTP_X_FORWARDED_FOR']) ? $_SERVER['REMOTE_ADDR'] : $_SERVER['HTTP_X_FORWARDED_FOR']),
            array('title' => 'Last logins', 'value' => $entries)
        );
	}
}
