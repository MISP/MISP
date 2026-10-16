<?php

/**
 * Which attributes name infrastructure: a network type outside External
 * analysis, or a template field that stores an address as text.
 */
class NetworkIndicators
{
    const TYPES = [
        'ip-src', 'ip-dst', 'ip-src|port', 'ip-dst|port',
        'domain', 'domain|ip', 'hostname', 'hostname|port',
        'url', 'uri', 'onion-address',
    ];

    // Mostly links to write-ups.
    const EXCLUDED_CATEGORIES = ['External analysis'];

    const TEMPLATE_FIELDS = [
        'passive-dns' => ['rrname', 'rdata'],
        'passive-dns-dnsdbflex' => ['rrname'],
        'attacker-infra' => ['beacon_host', 'hostname', 'http_url'],
        'shadowserver-beacon-ttl-report' => ['hostname'],
        'shadowserver-beacon-url-overlap' => ['hostname', 'url'],
        'intelmq_event' => ['source.reverse_dns', 'destination.reverse_dns'],
    ];

    /**
     * Find conditions over Attribute, with Object joined.
     *
     * @return array
     */
    public static function conditions()
    {
        $any = [[
            'Attribute.type' => self::TYPES,
            'Attribute.category !=' => self::EXCLUDED_CATEGORIES,
        ]];
        foreach (self::TEMPLATE_FIELDS as $template => $fields) {
            $any[] = [
                'Object.name' => $template,
                'Attribute.object_relation' => $fields,
            ];
        }
        return ['OR' => $any];
    }
}
