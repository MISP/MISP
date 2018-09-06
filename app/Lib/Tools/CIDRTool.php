<?php

class CIDRTool
{
    public function CIDR($cidr)
    {
        list($address, $prefix) = explode('/', $cidr, 2);
        $address = decbin(ip2long($address));
        $address = substr("00000000000000000000000000000000", 0, 32 - strlen($address)) . $address;
        $min = '';
        $max = '';
        for ($i = 0; $i < $prefix; $i++) {
            $min .= $address[$i];
        }
        $max = $min;
        $min = str_pad($min, 32, '0', STR_PAD_RIGHT);
        $max = str_pad($max, 32, '1', STR_PAD_RIGHT);
        $minArray = array();
        $maxArray = array();
        $searchTermLeft = '';
        $searchTermMin = 0;
        $searchTermMax = 0;
        $results = array();
        for ($i = 0; $i < 4; $i++) {
            $minArray[] = bindec(substr($min, ($i*8), 8));
            $maxArray[] = bindec(substr($max, ($i*8), 8));
            if ($minArray[$i] === $maxArray[$i]) {
                $searchTermLeft .= $minArray[$i] . '.';
            } else {
                $searchTermMin = $minArray[$i];
                $searchTermMax = $maxArray[$i];
                break;
            }
        }
        $length = $i;
        for ($i = 0; $i < ($searchTermMax - $searchTermMin + 1); $i++) {
            $results[$i] = $searchTermLeft . ($searchTermMin + $i);
            if ($length < 3) {
                $results[$i] .= '.%';
            }
        }
        return $results;
    }

    public function checkCIDR($cidr, $ipVersion)
    {
        if (strpos($cidr, '/') === false || substr_count($cidr, '/') !== 1) {
            return false;
        }
        list($net, $maskbits) = explode('/', $cidr);
        if (!is_numeric($maskbits) || $maskbits < 0) {
            return false;
        }
        if ($ipVersion == 4) {
            return ($maskbits <= 32) && filter_var($net, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);
        } elseif ($ipVersion == 6) {
            return ($maskbits <= 128) && filter_var($net, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
        } else {
            throw new InvalidArgumentException('checkCIDR does only support IPv4 & IPv6');
        }
    }
}
