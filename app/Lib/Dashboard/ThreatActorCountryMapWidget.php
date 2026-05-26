<?php

/**
 * ThreatActorCountryMapWidget (dashboard v2) — geographic distribution
 * of all known threat actors in the MISP galaxy library.
 *
 * A deliberately simple companion to AttributeGeoMapWidget: instead of
 * geolocating recent event data, it tallies the `country` element of
 * every cluster in the `threat-actor` galaxy library, giving the spread
 * of the known-actor landscape itself — independent of what happens to
 * be in the local event data. Reuses the WorldMap renderer (no new
 * render kind, no glyph); returns the WorldMap contract
 * `['data' => [ISO => count], 'scope' => ...]`.
 *
 * Counting: each DISTINCT actor (galaxy cluster `uuid`) is counted once.
 * The `galaxy_clusters` table can carry several rows per actor — one per
 * imported galaxy version (e.g. APT1 exists at versions 335 and 341 with
 * the same uuid, both country CN) — so a raw `COUNT(*)` would inflate the
 * busiest countries (~2x on the dev box). `COUNT(DISTINCT
 * GalaxyCluster.uuid)` collapses those version rows and is correct
 * whether or not a given instance carries the duplicates.
 *
 * No ACL: the galaxy library is instance-wide reference data, not
 * per-user-restricted threat data, so this is a plain reference query —
 * none of AttributeGeoMapWidget's aggregate-exposure concern (DD-11)
 * applies. The country element is already stored as an ISO alpha-2 code.
 */
class ThreatActorCountryMapWidget
{
    public $title = 'Threat actor origins';
    public $category = 'events';
    public $render = 'WorldMap';
    public $description = 'Geographic distribution of all known threat actors in the MISP galaxy library, by their attributed country (each distinct actor counted once).';
    public $width = 3;
    public $height = 4;
    public $params = [
        'limit' => 'Limit to the top-N countries by threat-actor count. Leave empty for all.',
        'palette' => 'Colour scale for the map: accent (blue) / danger (red) / success (green) / warning (amber) / info (cyan). Defaults to danger (threat data).',
    ];
    public $schema = [
        'limit' => [
            'type' => 'int',
            'help' => 'Top-N countries by threat-actor count (leave empty for all).',
        ],
        'palette' => [
            'type' => 'enum',
            'enum' => ['accent', 'danger', 'success', 'warning', 'info'],
            'default' => 'danger',
            'help' => 'Colour scale for the map. Defaults to red — this widget carries threat data.',
        ],
    ];
    public $cacheLifetime = false;
    public $autoRefreshDelay = false;
    public $placeholder =
'{
    "limit": 20
}';

    public function handler($user, $options = array())
    {
        $galaxyElement = ClassRegistry::init('GalaxyElement');
        $rows = $galaxyElement->find('all', [
            'recursive' => -1,
            'fields' => ['GalaxyElement.value', 'COUNT(DISTINCT GalaxyCluster.uuid) AS actor_count'],
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
                    'conditions' => ['Galaxy.id = GalaxyCluster.galaxy_id', 'Galaxy.type' => 'threat-actor'],
                ],
            ],
            'conditions' => ['GalaxyElement.key' => 'country'],
            'group' => ['GalaxyElement.value'],
            'order' => ['actor_count DESC'],
        ]);
        $limit = (!empty($options['limit']) && (int)$options['limit'] > 0) ? (int)$options['limit'] : 0;
        $data = [];
        foreach ($rows as $row) {
            $iso = isset($row['GalaxyElement']['value']) ? strtoupper(trim($row['GalaxyElement']['value'])) : '';
            if (!preg_match('/^[A-Z]{2}$/', $iso)) {
                continue;
            }
            $data[$iso] = (int)$row[0]['actor_count'];
            if ($limit > 0 && count($data) >= $limit) {
                break;
            }
        }
        return [
            'data' => $data,
            'scope' => 'Threat actors',
            // Named palette (DD-13); default red — this is threat data.
            // Overridable per widget instance via the configure form.
            'palette' => !empty($options['palette']) ? $options['palette'] : 'danger',
        ];
    }
}
