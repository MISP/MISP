<?php
App::uses('CidrTool', 'Tools');

class ClientIpTool
{
    /**
     * @param array $server $_SERVER-style array
     * @param string|null $header Name of the server variable holding the forwarded address chain
     * @param string|array|null $trustedProxies IP addresses or CIDR ranges, array or comma-separated string
     * @return string|null
     */
    public static function resolve(array $server, $header, $trustedProxies = null)
    {
        $remoteAddr = $server['REMOTE_ADDR'] ?? null;
        if (empty($header) || $header === 'REMOTE_ADDR' || !isset($server[$header]) || !is_string($server[$header])) {
            return $remoteAddr;
        }

        $proxies = self::parseList($trustedProxies);
        $cidrTool = new CidrTool($proxies);
        // The header is only believed when the request came through a known proxy
        if (!empty($proxies) && ($remoteAddr === null || !$cidrTool->contains($remoteAddr))) {
            return $remoteAddr;
        }

        $entries = array_map('trim', explode(',', $server[$header]));
        $client = $entries[0];
        for ($i = count($entries) - 1; $i >= 0; $i--) {
            if (empty($proxies) || !filter_var($entries[$i], FILTER_VALIDATE_IP) || !$cidrTool->contains($entries[$i])) {
                $client = $entries[$i];
                break;
            }
        }

        return filter_var($client, FILTER_VALIDATE_IP) ? $client : $remoteAddr;
    }

    /**
     * @param string|array|null $list
     * @return string[]
     */
    private static function parseList($list)
    {
        if (is_string($list)) {
            $list = explode(',', $list);
        }
        if (!is_array($list)) {
            return [];
        }
        return array_values(array_filter(array_map('trim', $list), 'strlen'));
    }
}
