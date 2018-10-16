<?php
App::uses('AppModel', 'Model');
App::uses('ConnectionManager', 'Model');
App::uses('Sanitize', 'Utility');

class Bruteforce extends AppModel
{
    public function insert($ip, $username)
    {
        $this->Log = ClassRegistry::init('Log');
        $this->Log->create();
        $expire = time() + Configure::read('SecureAuth.expire');
        $expire = date('Y-m-d H:i:s', $expire);
        $bruteforceEntry = array(
            'ip' => $ip,
            'username' => $username,
            'expire' => $expire
        );
        $this->save($bruteforceEntry);
        $title = 'Failed login attempt using username ' . $username . ' from IP: ' . $_SERVER['REMOTE_ADDR'] . '.';
        if ($this->isBlacklisted($ip, $username)) {
            $title .= 'This has tripped the bruteforce protection after  ' . Configure::read('SecureAuth.amount') . ' failed attempts. The user is now blacklisted for ' . Configure::read('SecureAuth.expire') . ' seconds.';
        }
        $log = array(
                'org' => 'SYSTEM',
                'model' => 'User',
                'model_id' => 0,
                'email' => $username,
                'action' => 'login_fail',
                'title' => $title
        );
        $this->Log->save($log);
    }

    public function clean()
    {
        $dataSourceConfig = ConnectionManager::getDataSource('default')->config;
        $dataSource = $dataSourceConfig['datasource'];
        if ($dataSource == 'Database/Mysql') {
            $sql = 'DELETE FROM bruteforces WHERE `expire` <= NOW();';
        } elseif ($dataSource == 'Database/Postgres') {
            $sql = 'DELETE FROM bruteforces WHERE expire <= NOW();';
        }
        $this->query($sql);
    }

    public function isBlacklisted($ip, $username)
    {
        // first remove old expired rows
        $this->clean();
        // count
        $params = array('conditions' => array(
                        'Bruteforce.ip' => $ip,
                        'Bruteforce.username' => $username),);
        $count = $this->find('count', $params);
        if ($count >= Configure::read('SecureAuth.amount')) {
            return true;
        } else {
            return false;
        }
    }
}
