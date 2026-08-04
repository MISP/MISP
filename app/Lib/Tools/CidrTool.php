<?php
class CidrTool
{
    /** @var array */
    private $ipv4 = [];

    /**
     * Minimum netmask for IPv4 in list. 33 because maximum netmask is 32..
     * @var int
     */
    private $minimumIpv4Mask = 33;

    /** @var array */
    private $ipv6 = [];

    public function __construct(array $list)
    {
        $this->filterInputList($list);
    }

    /**
     * @param string $value IPv4 or IPv6 address or range
     * @return false|string
     */
    public function contains($value)
    {
        $valueMask = null;
        if (str_contains($value, '/')) {
            list($value, $valueMask) = explode('/', $value);
        }

        $match = false;
        if (filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            // This code converts IP address to all possible CIDRs that can contains given IP address
            // and then check if given hash table contains that CIDR.
            $ip = ip2long($value);
            // Start from 1, because doesn't make sense to check 0.0.0.0/0 match
            for ($bits = $this->minimumIpv4Mask; $bits <= 32; $bits++) {
                $mask = -1 << (32 - $bits);
                $needle = long2ip($ip & $mask) . "/$bits";
                if (isset($this->ipv4[$needle])) {
                    $match = $needle;
                    break;
                }
            }

        } elseif (filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $value = unpack('n*', inet_pton($value));
            foreach ($this->ipv6 as $netmask => $lv) {
                foreach ($lv as $l) {
                    if ($this->ipv6InCidr($value, $l, $netmask)) {
                        $match = inet_ntop($l) . "/$netmask";
                        break;
                    }
                }
            }
        }

        if ($match && $valueMask) {
            $matchMask = explode('/', $match)[1];
            if ($valueMask < $matchMask) {
                return false;
            }
        }

        return $match;
    }

    /**
     * @param string $cidr
     * @return bool
     */
    public static function validate($cidr)
    {
        $parts = explode('/', $cidr, 2);
        $ipBytes = inet_pton($parts[0]);
        if ($ipBytes === false) {
            return false;
        }

        if (isset($parts[1])) {
            if (!ctype_digit($parts[1])) {
                return false;
            }

            $maximumNetmask = strlen($ipBytes) === 4 ? 32 : 128;
            if ($parts[1] > $maximumNetmask || $parts[1] < 0) {
                return false; // Netmask part of CIDR is invalid
            }
        }

        return true;
    }

    /**
     * Using solution from https://github.com/symfony/symfony/blob/master/src/Symfony/Component/HttpFoundation/IpUtils.php
     *
     * @param array $ip
     * @param string $cidr
     * @param int $netmask
     * @return bool
     */
    private function ipv6InCidr($ip, $cidr, $netmask)
    {
        $bytesAddr = unpack('n*', $cidr);
        for ($i = 1, $ceil = ceil($netmask / 16); $i <= $ceil; ++$i) {
            $left = $netmask - 16 * ($i - 1);
            $left = ($left <= 16) ? $left : 16;
            $mask = ~(0xffff >> $left) & 0xffff;
            if (($bytesAddr[$i] & $mask) != ($ip[$i] & $mask)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Filter out invalid IPv4 or IPv4 CIDR and append maximum netmask if no netmask is given.
     * @param array $list
     */
    private function filterInputList(array $list)
    {
        foreach ($list as $v) {
            $parts = explode('/', $v, 2);
            $ipBytes = inet_pton($parts[0]);
            if ($ipBytes === false) {
                continue; // IP address part of CIDR is invalid
            }
            $maximumNetmask = strlen($ipBytes) === 4 ? 32 : 128;

            if (isset($parts[1]) && ($parts[1] > $maximumNetmask || $parts[1] < 0)) {
                // Netmask part of CIDR is invalid
                continue;
            }

            $mask = $parts[1] ?? $maximumNetmask;
            if ($maximumNetmask === 32) {
                if ($mask < $this->minimumIpv4Mask) {
                    $this->minimumIpv4Mask = (int)$mask;
                }
                if (!isset($parts[1])) {
                    $v = "$v/$maximumNetmask"; // If CIDR doesnt contains '/', we will consider CIDR as /32
                }
                $this->ipv4[$v] = true;
            } else {
                $this->ipv6[$mask][] = $ipBytes;
            }
        }
    }
}
