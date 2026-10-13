<?php

/**
 * What is listening on an address.
 *
 * Two templates, and they are not the same answer at two levels of
 * detail: `ip-port` is a scan result and `http-request` is one
 * service's own description of itself. Both are drawn here because an
 * analyst reads them as one question — *what is exposed* — and
 * splitting them would give the same host two widgets.
 *
 * **Notable is a short, stated list and not a judgement engine.** A
 * compact widget has room for a count and about three port numbers,
 * and picking the three lowest or the three first would show 80 and
 * 443 on every host on the internet. The list below is the ports
 * whose presence changes what an analyst does next — remote access,
 * databases, and administrative interfaces that are not meant to face
 * outward. It is an opinion, it is small, and it is in code rather
 * than in a profile because it is about what the protocols are rather
 * than about what a team cares about.
 */
class PortServiceSetRenderer extends ValueRendererBase
{
    public $id = 'port-service-set';

    public $templates = array('ip-port', 'http-request');

    public $compact = 'Values/Renderers/port_service_set_compact';

    public $full = 'Values/Renderers/port_service_set_full';

    public $eventUse = self::EVENT_EACH;

    /** The relations naming the host an `ip-port` object is about. */
    const HOST = array('hostname', 'domain', 'ip', 'ip-dst', 'ip-src');

    /** Port => what it being open tells a reader. */
    const NOTABLE = array(
        21 => 'FTP',
        22 => 'SSH',
        23 => 'Telnet',
        135 => 'RPC',
        139 => 'NetBIOS',
        445 => 'SMB',
        1433 => 'MSSQL',
        3306 => 'MySQL',
        3389 => 'RDP',
        5432 => 'PostgreSQL',
        5900 => 'VNC',
        6379 => 'Redis',
        9200 => 'Elasticsearch',
        11211 => 'Memcached',
        27017 => 'MongoDB',
    );

    public function __construct()
    {
        $this->description = __('The ports and services an address'
            . ' exposes.');
    }

    public function subjectsOf(array $object)
    {
        $host = ($object['name'] ?? null) === 'http-request'
            ? $this->value($object, 'host')
            : $this->firstValue($object, self::HOST);
        return $host === null ? array() : array($host);
    }

    public function matches(array $objects, array $attributes)
    {
        foreach ($objects as $object) {
            if (!empty($this->servicesOf($object))) {
                return true;
            }
        }
        return false;
    }

    public function prepare(array $objects, array $attributes)
    {
        $services = array();
        foreach ($objects as $object) {
            foreach ($this->servicesOf($object) as $service) {
                $key = $service['port'] . '/' . $service['protocol'];
                if (!isset($services[$key])) {
                    $services[$key] = $service;
                    continue;
                }
                $held = $services[$key];
                if ($held['banner'] === null
                    && $service['banner'] !== null
                ) {
                    $services[$key]['banner'] = $service['banner'];
                }
                if (!in_array($service['module'], $held['sources'],
                    true)
                ) {
                    $services[$key]['sources'][] = $service['module'];
                }
            }
        }
        $services = array_values($services);
        usort($services, function ($a, $b) {
            return $a['port'] - $b['port'];
        });
        $notable = array();
        foreach ($services as $service) {
            if (isset(self::NOTABLE[$service['port']])) {
                $notable[] = $service;
            }
        }
        return array(
            'services' => $services,
            'count' => count($services),
            'notable' => $notable,
            'sources' => $this->sources($objects),
        );
    }

    /**
     * @param array $object
     * @return array
     */
    private function servicesOf(array $object)
    {
        if (($object['name'] ?? null) === 'http-request') {
            return $this->httpRequest($object);
        }
        return $this->ipPort($object);
    }

    /**
     * @param array $object
     * @return array
     */
    private function ipPort(array $object)
    {
        $out = array();
        /*
         * `dst-port` is the listening side and `src-port` is whoever
         * connected, so only one of the two is a service. A read that
         * took both would report an ephemeral port as an exposure.
         */
        foreach ($this->values($object, 'dst-port') as $port) {
            if (!ctype_digit(trim($port))) {
                continue;
            }
            $out[] = array(
                'port' => (int)$port,
                'protocol' => $this->value($object, 'protocol')
                    ?? 'tcp',
                'service' => self::NOTABLE[(int)$port] ?? null,
                'banner' => $this->value($object, 'text'),
                'host' => $this->firstValue($object, self::HOST),
                'first' => $this->stamp(
                    $this->value($object, 'first-seen')
                ),
                'last' => $this->stamp(
                    $this->value($object, 'last-seen')
                ),
                'module' => $object['module'] ?? null,
                'sources' => array($object['module'] ?? null),
            );
        }
        return $out;
    }

    /**
     * A described service, whose port is in its URL where it is
     * anywhere.
     *
     * @param array $object
     * @return array
     */
    private function httpRequest(array $object)
    {
        $url = $this->firstValue($object, array('url', 'uri'));
        $host = $this->value($object, 'host');
        if ($url === null && $host === null) {
            return array();
        }
        $port = null;
        if ($url !== null) {
            $parsed = parse_url($url);
            $port = $parsed['port'] ?? null;
            if ($port === null && isset($parsed['scheme'])) {
                $port = strtolower($parsed['scheme']) === 'https'
                    ? 443
                    : (strtolower($parsed['scheme']) === 'http'
                        ? 80
                        : null);
            }
        }
        if ($port === null) {
            return array();
        }
        return array(array(
            'port' => (int)$port,
            'protocol' => 'tcp',
            'service' => self::NOTABLE[(int)$port] ?? 'HTTP',
            'banner' => $this->firstValue($object, array(
                'content-type', 'header',
            )),
            'host' => $host,
            'first' => null,
            'last' => null,
            'module' => $object['module'] ?? null,
            'sources' => array($object['module'] ?? null),
        ));
    }
}
