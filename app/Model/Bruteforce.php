<?php
App::uses('AppModel', 'Model');
/**
 * Bruteforce Model
 *
 */
class Bruteforce extends AppModel {


    function insert($ip, $username) {
//         $this->data['Bruteforce']['ip'] = $ip;
//         $this->data['Bruteforce']['username'] = $username;
        $expire = Configure::read('SecureAuth.expire');

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
