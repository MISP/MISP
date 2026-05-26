<?php

/**
 * AttributeGeoMapWidget (dashboard v2) — geolocate recent MISP data
 * onto the WorldMap.
 *
 * Renders a choropleth world map of where recent MISP data points,
 * aggregated to ISO alpha-2 country codes and fed to the existing
 * `WorldMap` renderer (no new render kind, no new glyph). The data
 * shape returned is the WorldMap contract:
 *   ['data' => ['XX' => count, ...], 'scope' => '...']
 * (`drilldown` is intentionally omitted — see DD-11: the IP→country
 * mapping is computed transiently per render and never persisted, so
 * there is nothing stable to link a region to.)
 *
 * It blends up to four independently-selectable sources (config key
 * `sources`, default all on), each producing ISO alpha-2 tallies that
 * are summed:
 *
 *   - 'ip'             IP indicators geolocated via the MISP-managed
 *                      GeoOpen-Country mmdb (the same DB userprofiles
 *                      uses). Types ip-src / ip-dst / ip-src|port /
 *                      ip-dst|port carry the IP in value1; the
 *                      composite domain|ip carries it in value2.
 *   - 'domain_tld'     country-code TLD of domain / domain|ip (value1)
 *                      mapped to a country via the `country` galaxy's
 *                      own tld→ISO elements. A deliberately weak signal
 *                      (repurposed ccTLDs like .io/.tv/.co mislabel),
 *                      so only exact 2-letter ccTLDs present in the
 *                      galaxy are honoured; everything else is dropped.
 *   - 'country_galaxy' events tagged with a `misp-galaxy:country=...`
 *                      cluster, resolved to ISO via the cluster's `ISO`
 *                      galaxy element (SQL join, no JSON parse).
 *   - 'threat_actor'   events tagged with a `misp-galaxy:threat-actor=...`
 *                      cluster, resolved via the cluster's `country`
 *                      galaxy element (already stored as ISO alpha-2).
 *   - 'asn'            `AS` attributes mapped to a country via an
 *                      offline-derived ASN→dominant-country lookup
 *                      (`asn-country.json`, built by
 *                      `app/files/scripts/generate_asn_country_map.py`
 *                      from GeoOpen-Country-ASN.mmdb — DD-12). The mmdb
 *                      is IP-keyed and cannot map a bare ASN directly,
 *                      so the lookup approximates each ASN as the
 *                      country in which it announces the most IPv4
 *                      space. Regenerate the JSON when the mmdb updates.
 *
 * Note the map intentionally mixes *indicator location* (ip / tld)
 * with *attribution / relevance* (country_galaxy / threat_actor); the
 * per-source toggle lets a user isolate either reading. A single
 * attribute may also contribute more than one signal — e.g. domain|ip
 * counts once for its IP and once for its ccTLD — which is treated as
 * two independent signals, not double counting of one fact.
 *
 * Performance / ACL (DD-11). To stay viable on large instances this
 * widget deliberately does NOT enforce per-user ACL: the per-source
 * queries are bare `find('column')` / join fetches over the timeframe,
 * mirroring the posture of the global Statistics endpoint. Only
 * aggregate per-country counts are exposed (no values, no drilldown,
 * no attribution to a reporting org), and the widget is available to
 * all users. The safety bound against timeouts is a per-source cap on
 * the most-recent rows scanned (`limit`, default 10000) plus the
 * recency window (`time_window`, default 30 days, toolbar-reachable).
 * The GeoIp2 Reader is opened once and reused across the whole IP
 * sweep (UserLoginProfile::countryByIp opens a fresh Reader per call —
 * wasteful for thousands of IPs).
 */
class AttributeGeoMapWidget
{
    public $title = 'Recent data geolocation map';
    public $category = 'events';
    public $render = 'WorldMap';
    public $description = 'Geolocates recent MISP data onto a world map: IP indicators (GeoIP), domain ccTLDs, AS numbers, and country / threat-actor galaxy clusters attached to events. Each source is individually selectable.';
    public $width = 3;
    public $height = 4;
    public $params = [
        'time_window' => 'The time window, going back in seconds, that should be included (also accepts "30d" day form, or -1 for all historic data).',
        'sources' => 'Which geolocation sources to include, any of: "ip", "domain_tld", "asn", "country_galaxy", "threat_actor". Defaults to all five.',
        'limit' => 'Per-source cap on the most-recent rows scanned, to avoid timeouts on large instances. Default 10000.',
        'palette' => 'Colour scale for the map: accent (blue) / danger (red) / success (green) / warning (amber) / info (cyan). Defaults to danger (threat data).',
        'projection' => 'Map projection: mercator / equirectangular (flat lon/lat grid) / naturalEarth (default) / robinson (rounded, less polar-distorted world views) / peters (Gall-Peters equal-area).',
    ];
    public $schema = [
        'time_window' => [
            'type' => 'time_window',
            'default' => 'P30D',
            'help' => 'Recency window over which data is geolocated (last N days/hours, or all time). Toolbar-reachable.',
        ],
        'limit' => [
            'type' => 'int',
            'default' => 10000,
            'help' => 'Per-source cap on the most-recent rows scanned (default 10000).',
        ],
        'palette' => [
            'type' => 'enum',
            'enum' => ['accent', 'danger', 'success', 'warning', 'info'],
            'default' => 'danger',
            'help' => 'Colour scale for the map. Defaults to red — this widget carries threat data.',
        ],
        'projection' => [
            'type' => 'enum',
            'enum' => ['mercator', 'equirectangular', 'naturalEarth', 'robinson', 'peters'],
            'default' => 'naturalEarth',
            'help' => 'Map projection. Mercator (web-map look) / equirectangular (flat grid) / Natural Earth (default) / Robinson (rounded, less polar distortion) / Gall-Peters (equal-area).',
        ],
    ];
    // cacheLifetime is inert in dashboard v2 (renderWidget does not cache
    // and __extractMeta does not surface it); the bounded queries + cap
    // are the real perf guard. autoRefreshDelay=false: never re-run the
    // geo sweep on a timer — recompute only on page load / manual refresh.
    public $cacheLifetime = false;
    public $autoRefreshDelay = false;
    public $placeholder =
'{
    "time_window": "30d",
    "sources": ["ip", "domain_tld", "asn", "country_galaxy", "threat_actor"],
    "limit": 10000
}';

    // Mirrors UserLoginProfile::GEOIP_DB_FILE — the MISP-managed
    // GeoOpen-Country database (https://data.public.lu/...).
    const GEOIP_DB_FILE = APP . 'files' . DS . 'geo-open' . DS . 'GeoOpen-Country.mmdb';
    // Offline-derived ASN→dominant-country lookup (DD-12), built from
    // GeoOpen-Country-ASN.mmdb by generate_asn_country_map.py.
    const ASN_COUNTRY_MAP_FILE = APP . 'files' . DS . 'geo-open' . DS . 'asn-country.json';

    private $allSources = ['ip', 'domain_tld', 'asn', 'country_galaxy', 'threat_actor'];
    private $asnMapCache = null;

    public function handler($user, $options = array())
    {
        $since = $this->resolveSince($options);
        $cap = (!empty($options['limit']) && (int)$options['limit'] > 0) ? (int)$options['limit'] : 10000;
        $sources = $this->resolveSources($options);

        $data = [];
        if (in_array('ip', $sources, true)) {
            $this->mergeCounts($data, $this->ipCounts($since, $cap));
        }
        if (in_array('domain_tld', $sources, true)) {
            $this->mergeCounts($data, $this->domainTldCounts($since, $cap));
        }
        if (in_array('asn', $sources, true)) {
            $this->mergeCounts($data, $this->asnCounts($since, $cap));
        }
        if (in_array('country_galaxy', $sources, true)) {
            $this->mergeCounts($data, $this->eventGalaxyCounts('country', 'ISO', $since, $cap));
        }
        if (in_array('threat_actor', $sources, true)) {
            $this->mergeCounts($data, $this->eventGalaxyCounts('threat-actor', 'country', $since, $cap));
        }

        return [
            'data' => $data,
            'scope' => 'Recent MISP data by country',
            // Named palette (DD-13); default red — this is threat data.
            // Overridable per widget instance via the configure form.
            'palette' => !empty($options['palette']) ? $options['palette'] : 'danger',
            // Map projection (DD-14); default naturalEarth (DD-17), overridable.
            'projection' => !empty($options['projection']) ? $options['projection'] : 'naturalEarth',
        ];
    }

    /**
     * Resolve the recency lower bound (unix ts), or null for all-time.
     * Mirrors TrendingAttributesWidget's parsing; the CanonicalTypeAdapter
     * translates the P30D schema default / toolbar value into the "30d"
     * day form before we get here.
     */
    private function resolveSince($options)
    {
        $raw = isset($options['time_window']) && $options['time_window'] !== '' ? $options['time_window'] : '30d';
        if (is_string($raw) && substr($raw, -1) === 'd') {
            $window = ((int)substr($raw, 0, -1)) * 24 * 60 * 60;
        } else {
            $window = (int)$raw;
        }
        if ($window === -1) {
            return null;
        }
        if ($window <= 0) {
            $window = 30 * 24 * 60 * 60;
        }
        return time() - $window;
    }

    private function resolveSources($options)
    {
        $sources = isset($options['sources']) ? $options['sources'] : $this->allSources;
        if (!is_array($sources)) {
            $sources = [$sources];
        }
        $sources = array_values(array_intersect($this->allSources, $sources));
        return empty($sources) ? $this->allSources : $sources;
    }

    private function mergeCounts(array &$data, array $counts)
    {
        foreach ($counts as $iso => $n) {
            $data[$iso] = (isset($data[$iso]) ? $data[$iso] : 0) + $n;
        }
    }

    /**
     * Source 'ip': geolocate recent IP indicators via the GeoOpen mmdb.
     * value1 for ip-src/ip-dst/ip-src|port/ip-dst|port, value2 for the
     * composite domain|ip. No ACL (DD-11); capped + recency-bounded.
     */
    private function ipCounts($since, $cap)
    {
        $attribute = ClassRegistry::init('MispAttribute');
        $ips = array_merge(
            $this->fetchAttributeValues($attribute, ['ip-src', 'ip-dst', 'ip-src|port', 'ip-dst|port'], 'value1', $since, $cap),
            $this->fetchAttributeValues($attribute, ['domain|ip'], 'value2', $since, $cap)
        );
        return $this->geolocateIps($ips);
    }

    /**
     * Source 'domain_tld': map the ccTLD of recent domain / domain|ip
     * (value1) attributes to a country via the galaxy tld→ISO table.
     */
    private function domainTldCounts($since, $cap)
    {
        $attribute = ClassRegistry::init('MispAttribute');
        $domains = $this->fetchAttributeValues($attribute, ['domain', 'domain|ip'], 'value1', $since, $cap);
        $tldMap = $this->tldToIso();
        if (empty($tldMap)) {
            return [];
        }
        $counts = [];
        foreach ($domains as $domain) {
            $iso = $this->ccTldIso($domain, $tldMap);
            if ($iso !== null) {
                $counts[$iso] = (isset($counts[$iso]) ? $counts[$iso] : 0) + 1;
            }
        }
        return $counts;
    }

    /**
     * Source 'asn': map recent `AS` attributes to a country via the
     * offline-derived ASN→dominant-country lookup (DD-12). Graceful
     * empty if the lookup file is absent (e.g. not yet generated).
     */
    private function asnCounts($since, $cap)
    {
        $map = $this->asnCountryMap();
        if (empty($map)) {
            return [];
        }
        $attribute = ClassRegistry::init('MispAttribute');
        $asns = $this->fetchAttributeValues($attribute, ['AS'], 'value1', $since, $cap);
        $counts = [];
        foreach ($asns as $asn) {
            if (!is_string($asn)) {
                continue;
            }
            // MISP stores AS values as bare numbers; tolerate a leading
            // "AS" and any leading zeros so they match the map keys
            // (canonical digit strings from the mmdb).
            $digits = ltrim(preg_replace('/[^0-9]/', '', $asn), '0');
            if ($digits === '' || !isset($map[$digits])) {
                continue;
            }
            $iso = $map[$digits];
            if (preg_match('/^[A-Z]{2}$/', $iso)) {
                $counts[$iso] = (isset($counts[$iso]) ? $counts[$iso] : 0) + 1;
            }
        }
        return $counts;
    }

    /**
     * Load + memoise the offline-derived ASN→ISO lookup (DD-12).
     * Returns [] if the file is missing or unparseable.
     */
    private function asnCountryMap()
    {
        if ($this->asnMapCache !== null) {
            return $this->asnMapCache;
        }
        $this->asnMapCache = [];
        if (file_exists(self::ASN_COUNTRY_MAP_FILE)) {
            $decoded = json_decode((string)file_get_contents(self::ASN_COUNTRY_MAP_FILE), true);
            if (is_array($decoded)) {
                $this->asnMapCache = $decoded;
            }
        }
        return $this->asnMapCache;
    }

    /**
     * Capped, recency-bounded flat list of a single attribute column.
     * Deliberately a bare find('column') — no ACL (DD-11), and (unlike
     * MispAttribute::fetchAttributes) no implicit object_id=0 filter, so
     * IPs/domains living inside objects are included.
     */
    private function fetchAttributeValues($attribute, array $types, $field, $since, $cap)
    {
        $conditions = [
            'Attribute.type' => $types,
            'Attribute.deleted' => 0,
        ];
        if ($since !== null) {
            $conditions['Attribute.timestamp >='] = $since;
        }
        return $attribute->find('column', [
            'fields' => ['Attribute.' . $field],
            'conditions' => $conditions,
            'recursive' => -1,
            'order' => ['Attribute.timestamp' => 'DESC'],
            'limit' => $cap,
        ]);
    }

    /**
     * Open the GeoOpen-Country Reader once and tally ISO codes across
     * the whole IP list. Returns an empty tally (graceful) if the
     * geoip2 lib or the mmdb file is unavailable. Per-IP lookups that
     * miss (private/reserved/IPv6-not-in-DB/malformed) are skipped.
     */
    private function geolocateIps(array $ips)
    {
        $counts = [];
        if (empty($ips) || !class_exists('GeoIp2\Database\Reader') || !file_exists(self::GEOIP_DB_FILE)) {
            return $counts;
        }
        try {
            $reader = new GeoIp2\Database\Reader(self::GEOIP_DB_FILE);
        } catch (Exception $e) {
            return $counts;
        }
        foreach ($ips as $ip) {
            if (!is_string($ip) || $ip === '') {
                continue;
            }
            try {
                $iso = $reader->country($ip)->country->isoCode;
            } catch (Exception $e) {
                continue;
            }
            // Guard against the mmdb's "None" placeholder for unallocated
            // ranges (and any other non-ISO value): only accept a real
            // 2-letter alpha-2 code.
            if (is_string($iso) && preg_match('/^[A-Z]{2}$/', $iso)) {
                $counts[$iso] = (isset($counts[$iso]) ? $counts[$iso] : 0) + 1;
            }
        }
        return $counts;
    }

    /**
     * Build a ccTLD→ISO map (e.g. '.fr' => 'FR') from the `country`
     * galaxy's own elements — a self-join pairing each cluster's `tld`
     * element with its `ISO` element. Single small query; reflects the
     * actually-imported galaxy rather than a hardcoded table.
     */
    private function tldToIso()
    {
        $galaxyElement = ClassRegistry::init('GalaxyElement');
        $rows = $galaxyElement->find('all', [
            'recursive' => -1,
            'fields' => ['GalaxyElement.value', 'Iso.value'],
            'joins' => [
                [
                    'table' => 'galaxy_clusters',
                    'alias' => 'GalaxyCluster',
                    'type' => 'inner',
                    'conditions' => ['GalaxyCluster.id = GalaxyElement.galaxy_cluster_id'],
                ],
                [
                    'table' => 'galaxies',
                    'alias' => 'Galaxy',
                    'type' => 'inner',
                    'conditions' => ['Galaxy.id = GalaxyCluster.galaxy_id', 'Galaxy.type' => 'country'],
                ],
                [
                    'table' => 'galaxy_elements',
                    'alias' => 'Iso',
                    'type' => 'inner',
                    'conditions' => ['Iso.galaxy_cluster_id = GalaxyElement.galaxy_cluster_id', 'Iso.key' => 'ISO'],
                ],
            ],
            'conditions' => ['GalaxyElement.key' => 'tld'],
        ]);
        $map = [];
        foreach ($rows as $row) {
            $tld = isset($row['GalaxyElement']['value']) ? strtolower(trim($row['GalaxyElement']['value'])) : '';
            $iso = isset($row['Iso']['value']) ? strtoupper(trim($row['Iso']['value'])) : '';
            if ($tld !== '' && $iso !== '' && $tld[0] === '.' && preg_match('/^[A-Z]{2}$/', $iso)) {
                $map[$tld] = $iso;
            }
        }
        return $map;
    }

    /**
     * Resolve a domain's ccTLD to an ISO code, or null. Only honours
     * exact 2-letter ccTLDs present in the galaxy map; gTLDs (.com) and
     * unknown suffixes return null and are dropped.
     */
    private function ccTldIso($domain, array $tldMap)
    {
        if (!is_string($domain)) {
            return null;
        }
        $domain = rtrim(strtolower(trim($domain)), '.');
        $pos = strrpos($domain, '.');
        if ($pos === false) {
            return null;
        }
        $tld = substr($domain, $pos); // includes the leading dot
        if (strlen($tld) !== 3) { // ".xx" — ccTLDs only
            return null;
        }
        return isset($tldMap[$tld]) ? $tldMap[$tld] : null;
    }

    /**
     * Sources 'country_galaxy' / 'threat_actor': tally ISO codes from
     * the galaxy cluster attached (via tag) to recent events. The ISO
     * lives in the cluster's `$elementKey` galaxy element, joined
     * server-side so no galaxy JSON is parsed. Capped + recency-bounded;
     * no ACL (DD-11).
     */
    private function eventGalaxyCounts($galaxyType, $elementKey, $since, $cap)
    {
        $eventTag = ClassRegistry::init('EventTag');
        $eventConditions = ['Event.id = EventTag.event_id'];
        if ($since !== null) {
            $eventConditions['Event.timestamp >='] = $since;
        }
        $isos = $eventTag->find('column', [
            'fields' => ['GalaxyElement.value'],
            'recursive' => -1,
            'joins' => [
                [
                    'table' => 'events',
                    'alias' => 'Event',
                    'type' => 'inner',
                    'conditions' => $eventConditions,
                ],
                [
                    'table' => 'tags',
                    'alias' => 'Tag',
                    'type' => 'inner',
                    'conditions' => ['Tag.id = EventTag.tag_id'],
                ],
                [
                    'table' => 'galaxy_clusters',
                    'alias' => 'GalaxyCluster',
                    'type' => 'inner',
                    'conditions' => ['GalaxyCluster.tag_name = Tag.name'],
                ],
                [
                    'table' => 'galaxies',
                    'alias' => 'Galaxy',
                    'type' => 'inner',
                    'conditions' => ['Galaxy.id = GalaxyCluster.galaxy_id', 'Galaxy.type' => $galaxyType],
                ],
                [
                    'table' => 'galaxy_elements',
                    'alias' => 'GalaxyElement',
                    'type' => 'inner',
                    'conditions' => ['GalaxyElement.galaxy_cluster_id = GalaxyCluster.id', 'GalaxyElement.key' => $elementKey],
                ],
            ],
            'order' => ['Event.timestamp' => 'DESC'],
            'limit' => $cap,
        ]);
        $counts = [];
        foreach ($isos as $iso) {
            $iso = is_string($iso) ? strtoupper(trim($iso)) : '';
            if (preg_match('/^[A-Z]{2}$/', $iso)) {
                $counts[$iso] = (isset($counts[$iso]) ? $counts[$iso] : 0) + 1;
            }
        }
        return $counts;
    }
}
