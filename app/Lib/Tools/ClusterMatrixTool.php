<?php
App::uses('EventMatrixTool', 'Tools/EventOverview');
App::uses('RedisTool', 'Tools');

/**
 * The galaxy cluster page's Matrix tab: the techniques of the matrix
 * galaxies a cluster meets on events (observed) or is linked to by galaxy
 * relations (declared), read for the cluster alone or with its similar
 * clusters.
 *
 * A relation names a UUID, and one UUID can be several cluster rows (a
 * technique in both the current and a retired ATT&CK galaxy), so every
 * cluster is widened to all the visible rows sharing its UUID.
 */
class ClusterMatrixTool
{
    const CAPS = [1000, 5000, 25000, 100000];
    const DEFAULT_CAP = 5000;
    const LAYERS = ['observed', 'declared'];
    const CACHE_PREFIX = 'misp:cluster_matrix:';
    const CACHE_TTL = 300;

    /** @var array */
    private $user;
    /** @var array GalaxyCluster row */
    private $cluster;
    /** @var GalaxyCluster */
    private $GalaxyCluster;
    /** @var array|null galaxy id => Galaxy row */
    private $matrixGalaxies = null;
    /** @var array galaxy id => skeleton */
    private $skeletons = [];
    /** @var array galaxy id => tag name => true */
    private $skeletonTags = [];

    /**
     * @param array $user
     * @param array $cluster GalaxyCluster row the user may view
     */
    public function __construct(array $user, array $cluster)
    {
        $this->user = $user;
        $this->cluster = $cluster;
        $this->GalaxyCluster = ClassRegistry::init('GalaxyCluster');
    }

    /**
     * @param mixed $value
     * @return int one of CAPS
     */
    public static function cap($value)
    {
        $value = (int)$value;
        return in_array($value, self::CAPS, true) ? $value : self::DEFAULT_CAP;
    }

    /**
     * The matrix galaxies the cluster reaches with the default reading,
     * for deciding whether the page has a Matrix tab at all.
     *
     * @return array galaxy id => [observed, declared]
     */
    public function reachOnLoad()
    {
        $scope = $this->scope(true);
        return $this->reach($this->observed($scope, true, self::DEFAULT_CAP), $this->declared($scope));
    }

    /**
     * Everything the tab draws for one reading.
     *
     * @param array $options layer, similar (bool), cap, galaxy, tab, off (relation types left out)
     * @return array
     */
    public function view(array $options)
    {
        $layer = in_array($options['layer'] ?? null, self::LAYERS, true) ? $options['layer'] : 'observed';
        $similar = !isset($options['similar']) || $options['similar'];
        $cap = self::cap($options['cap'] ?? null);
        $off = array_values(array_filter(array_map('strval', (array)($options['off'] ?? []))));

        $scope = $this->scope($similar);
        $observed = $this->observed($scope, $similar, $cap);
        $declared = $this->declared($scope);
        $reach = $this->reach($observed, $declared);

        $galaxyId = (int)($options['galaxy'] ?? 0);
        if (!isset($reach[$galaxyId])) {
            $galaxyId = $this->defaultGalaxy($reach);
        }
        $result = [
            'cluster' => ['id' => (int)$this->cluster['id'], 'value' => (string)$this->cluster['value']],
            'layer' => $layer,
            'similar' => $similar,
            'cap' => $cap,
            'caps' => self::CAPS,
            'off' => $off,
            'scope' => [],
            'events' => $observed['events'],
            'capped' => $observed['capped'],
            'reach' => [],
            'galaxy' => $galaxyId ?: null,
            'counts' => ['observed' => 0, 'declared' => 0],
            'relations' => [],
            'marks' => [],
            'matrix' => null,
        ];
        // One line per UUID and galaxy: duplicate rows in one galaxy are one cluster to the reader
        foreach ($scope as $member) {
            $result['scope'][$member['uuid'] . ':' . $member['galaxy_id']] = $result['scope'][$member['uuid'] . ':' . $member['galaxy_id']] ?? [
                'id' => $member['id'],
                'value' => $member['value'],
                'galaxy' => $member['galaxy_name'],
                'self' => $member['self'],
            ];
        }
        $result['scope'] = array_values($result['scope']);
        foreach ($reach as $id => $counts) {
            $result['reach'][] = ['id' => $id, 'name' => $this->matrixGalaxies()[$id]['name']] + $counts;
        }
        if (!$galaxyId) {
            return $result;
        }

        $result['counts'] = $reach[$galaxyId];
        $inSkeleton = $this->skeletonTags($galaxyId);
        $relations = [];
        foreach ($declared[$galaxyId] ?? [] as $tagName => $links) {
            if (isset($inSkeleton[$tagName])) {
                foreach ($links as $link) {
                    $relations[$link['relation']] = ($relations[$link['relation']] ?? 0) + 1;
                }
            }
        }
        arsort($relations);
        $result['relations'] = $relations;
        foreach ($scope as $member) {
            $result['marks'][$member['tag_name']] = $member['self'] ? 'self' : 'similar';
        }

        $byTag = $layer === 'observed'
            ? $this->observedCells($observed['galaxies'][$galaxyId] ?? [], $scope)
            : $this->declaredCells($declared[$galaxyId] ?? [], $scope, array_flip($off));
        $tab = isset($options['tab']) && is_string($options['tab']) ? $options['tab'] : $this->selfTab($galaxyId, $scope);
        $result['matrix'] = EventMatrixTool::layer(
            $this->skeleton($galaxyId),
            $this->matrixGalaxies()[$galaxyId],
            $byTag,
            $tab
        );
        return $result;
    }

    /**
     * The cluster and, with $similar, the clusters a `similar` relation
     * links it to either way, each widened to its UUID twins.
     *
     * @param bool $similar
     * @return array cluster id => id, uuid, value, tag_name, galaxy_id, galaxy_name, self
     */
    public function scope($similar)
    {
        $centre = $this->clustersByUuid([(string)$this->cluster['uuid']]);
        $centre[(int)$this->cluster['id']] = $centre[(int)$this->cluster['id']] ?? $this->member($this->cluster);
        foreach ($centre as $id => $member) {
            $centre[$id]['self'] = true;
        }
        if (!$similar) {
            return $centre;
        }
        $far = [];
        foreach ($this->relations($centre, ['similar']) as $relation) {
            $far[$relation['far']] = true;
        }
        foreach ($this->clustersByUuid(array_keys($far)) as $id => $member) {
            if (!isset($centre[$id])) {
                $centre[$id] = $member + ['self' => false];
            }
        }
        return $centre;
    }

    /**
     * The latest $cap events the user can see carrying a scope tag, and the
     * matrix techniques on them, each at event or attribute level.
     *
     * @param array $scope as scope() returns it
     * @param bool $similar the scope's key in the cache
     * @param int $cap
     * @return array events read, capped, galaxies => galaxy id => tag name => [events, via => member ids]
     */
    public function observed(array $scope, $similar, $cap)
    {
        $key = self::CACHE_PREFIX . (int)$this->user['id'] . ':' . (int)$this->cluster['id'] . ':' . ($similar ? 1 : 0) . ':' . (int)$cap;
        $redis = null;
        try {
            $redis = RedisTool::init();
            $hit = $redis->get($key);
            if ($hit !== false) {
                return RedisTool::deserialize($hit);
            }
        } catch (Exception $e) {
            $redis = null;
        }
        $observed = $this->readObserved($scope, $cap);
        if ($redis) {
            try {
                $redis->setex($key, self::CACHE_TTL, RedisTool::serialize($observed));
            } catch (Exception $e) {
                // Recomputed on the next request
            }
        }
        return $observed;
    }

    /**
     * Matrix clusters linked to a scope cluster by any galaxy relation,
     * either way. Relations between two scope clusters are what made the
     * scope, not knowledge about a technique, so they are left out.
     *
     * @param array $scope as scope() returns it
     * @return array galaxy id => tag name => list of [via => member id, relation, dir => out|in]
     */
    public function declared(array $scope)
    {
        $relations = $this->relations($scope);
        if (empty($relations)) {
            return [];
        }
        $scopeUuids = array_flip(array_column($scope, 'uuid'));
        $farUuids = array_diff(array_unique(array_column($relations, 'far')), array_keys($scopeUuids));
        $targets = $this->clustersByUuid(array_values($farUuids), array_keys($this->matrixGalaxies()));
        $byUuid = [];
        foreach ($targets as $target) {
            $byUuid[$target['uuid']][] = $target;
        }
        $declared = [];
        foreach ($relations as $relation) {
            $uuid = $relation['far'];
            if (isset($scopeUuids[$uuid]) || empty($byUuid[$uuid])) {
                continue;
            }
            $link = ['via' => $relation['near'], 'relation' => $relation['relation'], 'dir' => $relation['dir']];
            foreach ($byUuid[$uuid] as $target) {
                $links = &$declared[$target['galaxy_id']][$target['tag_name']];
                if (!in_array($link, (array)$links, true)) {
                    $links[] = $link;
                }
                unset($links);
            }
        }
        return $declared;
    }

    /**
     * @return array galaxy id => [observed, declared] lit cells, for the
     *         galaxies either layer lights, and the cluster's own matrix
     */
    private function reach(array $observed, array $declared)
    {
        $candidates = array_keys($observed['galaxies']);
        foreach (array_keys($declared) as $galaxyId) {
            $candidates[] = $galaxyId;
        }
        $own = (int)$this->cluster['galaxy_id'];
        if (isset($this->matrixGalaxies()[$own])) {
            $candidates[] = $own;
        }
        $reach = [];
        foreach (array_unique($candidates) as $galaxyId) {
            if (!isset($this->matrixGalaxies()[$galaxyId])) {
                continue;
            }
            $inSkeleton = $this->skeletonTags($galaxyId);
            $counts = [
                'observed' => count(array_intersect_key($observed['galaxies'][$galaxyId] ?? [], $inSkeleton)),
                'declared' => count(array_intersect_key($declared[$galaxyId] ?? [], $inSkeleton)),
            ];
            if ($galaxyId === $own || $counts['observed'] > 0 || $counts['declared'] > 0) {
                $reach[$galaxyId] = $counts;
            }
        }
        return $reach;
    }

    /**
     * The cluster's own galaxy, otherwise the one with the most observed
     * then declared cells.
     */
    private function defaultGalaxy(array $reach)
    {
        if (empty($reach)) {
            return 0;
        }
        $own = (int)$this->cluster['galaxy_id'];
        if (isset($reach[$own])) {
            return $own;
        }
        uasort($reach, function ($a, $b) {
            return [$b['observed'], $b['declared']] <=> [$a['observed'], $a['declared']];
        });
        return (int)array_key_first($reach);
    }

    /**
     * The first tab holding the cluster itself, so a technique opens on its
     * own cell; null lets the matrix pick its busiest tab.
     */
    private function selfTab($galaxyId, array $scope)
    {
        $self = [];
        foreach ($scope as $member) {
            if ($member['self']) {
                $self[$member['tag_name']] = true;
            }
        }
        $skeleton = $this->skeleton($galaxyId);
        $keys = array_map('strval', array_keys($skeleton['killChain']));
        foreach (array_keys($skeleton['tabs']) as $key) {
            if (!in_array((string)$key, $keys, true)) {
                $keys[] = (string)$key;
            }
        }
        foreach ($keys as $key) {
            foreach ($skeleton['tabs'][$key] ?? [] as $cells) {
                foreach ($cells as $cell) {
                    if (isset($self[$cell['tag_name']])) {
                        return $key;
                    }
                }
            }
        }
        return null;
    }

    private function observedCells(array $cells, array $scope)
    {
        $scopeTags = [];
        foreach ($scope as $member) {
            $scopeTags[] = $member['tag_id'];
        }
        $scopeTags = implode('|', array_filter(array_unique($scopeTags)));
        $byTag = [];
        foreach ($cells as $tagName => $cell) {
            $via = [];
            foreach ($cell['via'] as $memberId) {
                if (isset($scope[$memberId]) && !$scope[$memberId]['self']) {
                    $via[] = $scope[$memberId]['value'];
                }
            }
            $byTag[$tagName] = $this->hit('event', $cell['events'], [
                'v' => array_values(array_unique($via)),
                'h' => '/events/index/searchtag:' . $scopeTags . '/searchtags:' . $cell['tag_id'],
            ]);
        }
        return $byTag;
    }

    private function declaredCells(array $cells, array $scope, array $off)
    {
        $byTag = [];
        foreach ($cells as $tagName => $links) {
            $shown = [];
            foreach ($links as $link) {
                if (!isset($off[$link['relation']]) && isset($scope[$link['via']])) {
                    $shown[] = [$scope[$link['via']]['value'], $link['relation'], $link['dir']];
                }
            }
            if (!empty($shown)) {
                $byTag[$tagName] = $this->hit('declared', 0, ['d' => $shown]);
            }
        }
        return $byTag;
    }

    private function hit($state, $events, array $extra)
    {
        return [
            'state' => $state,
            'onEvent' => $state === 'event',
            'events' => (int)$events,
            'indicators' => 0,
            'loose' => 0,
            'foreign' => false,
            'origins' => [],
            'extra' => $extra,
        ];
    }

    private function readObserved(array $scope, $cap)
    {
        $empty = ['events' => 0, 'capped' => false, 'galaxies' => []];
        $tagToMember = [];
        foreach ($scope as $id => $member) {
            if (!empty($member['tag_id'])) {
                $tagToMember[$member['tag_id']][] = $id;
            }
        }
        if (empty($tagToMember)) {
            return $empty;
        }
        $Event = ClassRegistry::init('Event');
        $EventTag = ClassRegistry::init('EventTag');
        $Attribute = ClassRegistry::init('AttributeTag')->Attribute;
        $eventAcl = $Event->createEventConditions($this->user);
        $attributeAcl = $Attribute->buildConditions($this->user);
        $scopeTagIds = array_keys($tagToMember);

        // Two bounded reads merged here: an OR across event and attribute
        // tags would cost the index on either.
        $latest = [];
        $hitLimit = false;
        $rows = $EventTag->find('all', [
            'recursive' => -1,
            'contain' => ['Event'],
            'fields' => ['EventTag.event_id', 'EventTag.tag_id', 'Event.timestamp'],
            'conditions' => ['AND' => [$eventAcl, ['EventTag.tag_id' => $scopeTagIds]]],
            'order' => ['Event.timestamp' => 'DESC'],
            'limit' => $cap,
        ]);
        $hitLimit = $hitLimit || count($rows) >= $cap;
        foreach ($rows as $row) {
            $eventId = (int)$row['EventTag']['event_id'];
            $latest[$eventId]['t'] = (int)$row['Event']['timestamp'];
            $latest[$eventId]['tags'][(int)$row['EventTag']['tag_id']] = true;
        }
        $rows = $Attribute->find('all', [
            'recursive' => -1,
            'contain' => empty($attributeAcl) ? ['Event'] : ['Event', 'Object'],
            'joins' => [[
                'table' => 'attribute_tags',
                'alias' => 'ScopeTag',
                'type' => 'INNER',
                'conditions' => ['ScopeTag.attribute_id = Attribute.id', 'ScopeTag.tag_id' => $scopeTagIds],
            ]],
            'fields' => ['Attribute.event_id', 'ScopeTag.tag_id', 'MAX(Event.timestamp) AS t'],
            'conditions' => ['AND' => [['Attribute.deleted' => 0], $attributeAcl]],
            'group' => ['Attribute.event_id', 'ScopeTag.tag_id'],
            'order' => ['MAX(Event.timestamp) DESC'],
            'limit' => $cap,
        ]);
        $hitLimit = $hitLimit || count($rows) >= $cap;
        foreach ($rows as $row) {
            $eventId = (int)$row['Attribute']['event_id'];
            $latest[$eventId]['t'] = (int)$row[0]['t'];
            $latest[$eventId]['tags'][(int)$row['ScopeTag']['tag_id']] = true;
        }
        if (empty($latest)) {
            return $empty;
        }
        uasort($latest, function ($a, $b) {
            return $b['t'] <=> $a['t'];
        });
        $capped = $hitLimit || count($latest) > $cap;
        $latest = array_slice($latest, 0, $cap, true);
        $eventIds = array_keys($latest);

        $matrixTags = $this->matrixTags();
        if (empty($matrixTags)) {
            return ['events' => count($eventIds), 'capped' => $capped, 'galaxies' => []];
        }
        $pairs = [];
        $rows = $EventTag->find('all', [
            'recursive' => -1,
            'fields' => ['EventTag.event_id', 'EventTag.tag_id'],
            'conditions' => ['EventTag.event_id' => $eventIds, 'EventTag.tag_id' => array_keys($matrixTags)],
        ]);
        foreach ($rows as $row) {
            $pairs[(int)$row['EventTag']['tag_id']][(int)$row['EventTag']['event_id']] = true;
        }
        $rows = $Attribute->find('all', [
            'recursive' => -1,
            'contain' => empty($attributeAcl) ? [] : ['Event', 'Object'],
            'joins' => [[
                'table' => 'attribute_tags',
                'alias' => 'MatrixTag',
                'type' => 'INNER',
                'conditions' => ['MatrixTag.attribute_id = Attribute.id', 'MatrixTag.tag_id' => array_keys($matrixTags)],
            ]],
            // On attribute_tags.event_id, so the planner can take (event_id, tag_id) for a
            // small window and the tag_id index when the window outweighs the tags
            'fields' => ['MatrixTag.event_id', 'MatrixTag.tag_id'],
            'conditions' => ['AND' => [['MatrixTag.event_id' => $eventIds, 'Attribute.deleted' => 0], $attributeAcl]],
            'group' => ['MatrixTag.event_id', 'MatrixTag.tag_id'],
        ]);
        foreach ($rows as $row) {
            $pairs[(int)$row['MatrixTag']['tag_id']][(int)$row['MatrixTag']['event_id']] = true;
        }

        $galaxies = [];
        foreach ($pairs as $tagId => $events) {
            $via = [];
            foreach (array_keys($events) as $eventId) {
                foreach (array_keys($latest[$eventId]['tags']) as $scopeTagId) {
                    foreach ($tagToMember[$scopeTagId] ?? [] as $memberId) {
                        $via[$memberId] = true;
                    }
                }
            }
            list($galaxyId, $tagName) = $matrixTags[$tagId];
            $galaxies[$galaxyId][$tagName] = [
                'events' => count($events),
                'tag_id' => $tagId,
                'via' => array_keys($via),
            ];
        }
        return ['events' => count($eventIds), 'capped' => $capped, 'galaxies' => $galaxies];
    }

    /**
     * @return array tag id => [galaxy id, tag name], for the tags of every
     *         matrix galaxy's clusters
     */
    private function matrixTags()
    {
        $rows = $this->GalaxyCluster->find('all', [
            'recursive' => -1,
            'fields' => ['GalaxyCluster.galaxy_id', 'Tag.id', 'Tag.name'],
            'joins' => [[
                'table' => 'tags',
                'alias' => 'Tag',
                'type' => 'INNER',
                'conditions' => ['Tag.name = GalaxyCluster.tag_name'],
            ]],
            'conditions' => [
                'GalaxyCluster.galaxy_id' => array_keys($this->matrixGalaxies()),
                'GalaxyCluster.deleted' => 0,
            ],
        ]);
        $tags = [];
        foreach ($rows as $row) {
            $tags[(int)$row['Tag']['id']] = [(int)$row['GalaxyCluster']['galaxy_id'], $row['Tag']['name']];
        }
        return $tags;
    }

    /**
     * Relations touching the members either way, read as two statements
     * (an OR across the two columns loses the index on either). The far end
     * is taken by UUID: a relation's referenced_galaxy_cluster_id goes stale
     * when the cluster it names is re-imported under a new id.
     *
     * @param array $members as scope() returns them
     * @param array|null $types relation types, null for any
     * @return array list of [near => member id, far => UUID, relation, dir => out|in]
     */
    private function relations(array $members, $types = null)
    {
        $Relation = $this->GalaxyCluster->GalaxyClusterRelation;
        $acl = $Relation->buildConditions($this->user, false);
        $byUuid = [];
        foreach ($members as $id => $member) {
            $byUuid[$member['uuid']] = $byUuid[$member['uuid']] ?? $id;
        }
        $reads = [
            'out' => ['GalaxyClusterRelation.galaxy_cluster_id' => array_keys($members)],
            'in' => ['GalaxyClusterRelation.referenced_galaxy_cluster_uuid' => array_keys($byUuid)],
        ];
        $out = [];
        foreach ($reads as $dir => $conditions) {
            if ($types !== null) {
                $conditions['GalaxyClusterRelation.referenced_galaxy_cluster_type'] = $types;
            }
            $rows = $Relation->find('all', [
                'recursive' => -1,
                'fields' => [
                    'GalaxyClusterRelation.galaxy_cluster_id',
                    'GalaxyClusterRelation.galaxy_cluster_uuid',
                    'GalaxyClusterRelation.referenced_galaxy_cluster_uuid',
                    'GalaxyClusterRelation.referenced_galaxy_cluster_type',
                ],
                'conditions' => ['AND' => [$conditions, $acl]],
            ]);
            foreach ($rows as $row) {
                $row = $row['GalaxyClusterRelation'];
                $out[] = [
                    'near' => $dir === 'out' ? (int)$row['galaxy_cluster_id'] : $byUuid[$row['referenced_galaxy_cluster_uuid']],
                    'far' => (string)($dir === 'out' ? $row['referenced_galaxy_cluster_uuid'] : $row['galaxy_cluster_uuid']),
                    'relation' => (string)$row['referenced_galaxy_cluster_type'],
                    'dir' => $dir,
                ];
            }
        }
        return $out;
    }

    /**
     * @param array $uuids
     * @param array|null $galaxyIds only clusters of these galaxies
     * @return array cluster id => member()
     */
    private function clustersByUuid(array $uuids, $galaxyIds = null)
    {
        if (empty($uuids)) {
            return [];
        }
        $conditions = ['GalaxyCluster.uuid' => array_values($uuids), 'GalaxyCluster.deleted' => 0];
        if ($galaxyIds !== null) {
            if (empty($galaxyIds)) {
                return [];
            }
            $conditions['GalaxyCluster.galaxy_id'] = $galaxyIds;
        }
        $rows = $this->GalaxyCluster->fetchGalaxyClusters($this->user, [
            'conditions' => $conditions,
            'fields' => [
                'GalaxyCluster.id', 'GalaxyCluster.uuid', 'GalaxyCluster.value',
                'GalaxyCluster.tag_name', 'GalaxyCluster.galaxy_id',
            ],
            'contain' => ['Galaxy' => ['fields' => ['Galaxy.name']]],
        ]);
        $members = [];
        foreach ($rows as $row) {
            $cluster = $row['GalaxyCluster'];
            $cluster['Galaxy'] = $cluster['Galaxy'] ?? $row['Galaxy'] ?? [];
            $members[(int)$cluster['id']] = $this->member($cluster);
        }
        $tagIds = empty($members) ? [] : ClassRegistry::init('Tag')->find('list', [
            'conditions' => ['Tag.name' => array_values(array_unique(array_column($members, 'tag_name')))],
            'fields' => ['Tag.name', 'Tag.id'],
        ]);
        foreach ($members as $id => $member) {
            $members[$id]['tag_id'] = isset($tagIds[$member['tag_name']]) ? (int)$tagIds[$member['tag_name']] : null;
        }
        return $members;
    }

    private function member(array $cluster)
    {
        return [
            'id' => (int)$cluster['id'],
            'uuid' => (string)$cluster['uuid'],
            'value' => (string)$cluster['value'],
            'tag_name' => (string)$cluster['tag_name'],
            'tag_id' => null,
            'galaxy_id' => (int)$cluster['galaxy_id'],
            'galaxy_name' => (string)($cluster['Galaxy']['name'] ?? ''),
            'self' => false,
        ];
    }

    /**
     * @return array galaxy id => Galaxy row, the matrix galaxies the user may see
     */
    private function matrixGalaxies()
    {
        if ($this->matrixGalaxies === null) {
            $Galaxy = $this->GalaxyCluster->Galaxy;
            $rows = $Galaxy->find('all', [
                'recursive' => -1,
                'conditions' => ['AND' => [
                    ['NOT' => ['Galaxy.kill_chain_order' => null]],
                    ['Galaxy.kill_chain_order !=' => ''],
                    $Galaxy->buildConditions($this->user),
                ]],
            ]);
            $this->matrixGalaxies = [];
            foreach ($rows as $row) {
                if (EventMatrixTool::isMatrixGalaxy($row['Galaxy'])) {
                    $this->matrixGalaxies[(int)$row['Galaxy']['id']] = $row['Galaxy'];
                }
            }
        }
        return $this->matrixGalaxies;
    }

    private function skeleton($galaxyId)
    {
        if (!isset($this->skeletons[$galaxyId])) {
            $this->skeletons[$galaxyId] = $this->GalaxyCluster->Galaxy->matrixSkeleton(
                $this->user,
                $this->matrixGalaxies()[$galaxyId]
            );
        }
        return $this->skeletons[$galaxyId];
    }

    private function skeletonTags($galaxyId)
    {
        if (!isset($this->skeletonTags[$galaxyId])) {
            $tags = [];
            foreach ($this->skeleton($galaxyId)['tabs'] as $columns) {
                foreach ($columns as $cells) {
                    foreach ($cells as $cell) {
                        $tags[$cell['tag_name']] = true;
                    }
                }
            }
            $this->skeletonTags[$galaxyId] = $tags;
        }
        return $this->skeletonTags[$galaxyId];
    }
}
