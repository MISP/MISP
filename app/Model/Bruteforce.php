<?php
App::uses('AppModel', 'Model');
App::uses('ConnectionManager', 'Model');
App::uses('Sanitize', 'Utility');

class Bruteforce extends AppModel
{
    public function insert($username)
    {
        $this->Log = ClassRegistry::init('Log');
        $this->Log->create();
        $ip = $this->_remoteIp();
        $expire = Configure::check('SecureAuth.expire') ? Configure::read('SecureAuth.expire') : 300;
        $amount = Configure::check('SecureAuth.amount') ? Configure::read('SecureAuth.amount') : 5;
        $expireTime = time() + $expire;
        $expireTime = date('Y-m-d H:i:s', $expireTime);
        $bruteforceEntry = array(
            'ip' => $ip,
            'username' => trim(strtolower($username)),
            'expire' => $expireTime
        );
        $this->save($bruteforceEntry);
        $title = 'Failed login attempt using username ' . $username . ' from IP: ' . $ip . '.';
        $this->UserLoginProfile = ClassRegistry::init('UserLoginProfile');
        $change = $this->UserLoginProfile->_getUserProfile();
        if ($this->isBlocklisted($username)) {
            $title .= ' Blocked against bruteforcing.';
            $change['details'] = 'This has tripped the bruteforce protection after  ' . $amount . ' failed attempts. The source IP/username is now blocklisted for ' . $expire . ' seconds.';
        }
        // lookup the real user details
        $this->User = ClassRegistry::init('User');
        $user = $this->User->find('first', array(
            'conditions' => array('User.email' => $username),
            'fields' => array('User.id', 'Organisation.name'),
            'recursive' => 0));
        if ($user) {
            $org = $user['Organisation']['name'];
            $userId = $user['User']['id'];
        } else {
            $org = 'SYSTEM';
            $userId = 0;
        }

        $log = array(
                'org' => $org,
                'model' => 'User',
                'model_id' => $userId,
                'email' => $username,
                'user_id' => $userId,
                'action' => 'login_fail',
                'title' => $title,
                'change' => json_encode($change)
        );
        $this->Log->save($log);
    }

    public function clean()
    {
        $expire = date('Y-m-d H:i:s', time());
        if ($this->isMysql()) {
            $sql = 'DELETE FROM bruteforces WHERE `expire` <= "' . $expire . '";';
        } else {
            $sql = 'DELETE FROM bruteforces WHERE expire <= \'' . $expire . '\';';
        }
        $this->query($sql);
    }

    public function isBlocklisted($username)
    {
        // first remove old expired rows
        $this->clean();
        // count
        $ip = $this->_remoteIp();
        $params = array(
            'conditions' => array(
            'Bruteforce.ip' => $ip,
            'LOWER(Bruteforce.username)' => trim(strtolower($username)))
        );
        $count = $this->find('count', $params);
        $amount = Configure::check('SecureAuth.amount') ? Configure::read('SecureAuth.amount') : 5;
        if ($count >= $amount) {
            return true;
        } else {
            return false;
        }
    }
}
