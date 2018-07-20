<?php

App::uses('AppModel', 'Model');

/*
 * Domain Name System related
 */
class Dns extends AppModel
{
    public $useTable = false;

    // Checks for a valid internet name
    // Returns true if the name is an existing domain name, false otherwise
    public function testipaddress($nametotest)
    {
        if (intval($nametotest) > 0) {
            return true;
        } else {
            $ipaddress = gethostbyname($nametotest);
            if ($ipaddress == $nametotest) {
                return false;
            } else {
                return true;
            }
        }
    }

    // Name to IP list
    // get all IP addresses of a certain domain name via DNS.
    public function nametoipl($name = '')
    {
        if ('true' == Configure::read('MISP.dns')) {
            if (!$ips = gethostbynamel($name)) {
                $ips = array();
            }
        } else {
            $ips = array();
        }
        return $ips;
    }
}
