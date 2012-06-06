<?php
App::uses('AppModel', 'Model');
App::uses('Sanitize', 'Utility');

/**
 * Bruteforce Model
 *
 */
class Bruteforce extends AppModel {


    function insert($ip, $username) {
        $expire = Configure::read('SecureAuth.expire');
        // sanitize fields
        $ip = Sanitize::clean($ip);
        $username = Sanitize::clean($username);
        $this->query("INSERT INTO `bruteforces` (`ip` , `username` , `expire` ) VALUES ('$ip', '$username', TIMESTAMPADD(SECOND,$expire, NOW()));");
    }


    function clean() {
        $this->query("DELETE FROM `bruteforces` WHERE `expire`<=NOW();");
    }

    function isBlacklisted($ip,$username) {
        // first remove old expired rows
        $this->clean();
        // count
        $params = array(
                'conditions' => array(
                        'Bruteforce.ip' => $ip,
                        'Bruteforce.username' => $username
                        ),
        );
        $count = $this->find('count', $params);
        if ($count >= Configure::read('SecureAuth.amount')) return true;
        else return false;
    }
}
