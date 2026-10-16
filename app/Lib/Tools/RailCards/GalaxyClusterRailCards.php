<?php
App::uses('LazyRailCards', 'Tools/RailCards');

/**
 * Rail cards for a galaxy cluster. $cluster is the output of
 * GalaxyCluster::fetchIfAuthorized($user, $id, 'view', true, true).
 */
class GalaxyClusterRailCards extends LazyRailCards
{
    const FACT_KEYS = [
        'synonyms', 'country', 'cfr-suspected-state-sponsor', 'attribution-confidence',
        'cfr-type-of-incident', 'cfr-target-category', 'kill_chain', 'external_id',
    ];

    private function factLabel($key)
    {
        $labels = [
            'synonyms' => __('Synonyms'),
            'country' => __('Country'),
            'cfr-suspected-state-sponsor' => __('Suspected sponsor'),
            'attribution-confidence' => __('Attribution confidence'),
            'cfr-type-of-incident' => __('Incident types'),
            'cfr-target-category' => __('Targets'),
            'kill_chain' => __('Kill chain'),
            'external_id' => __('External ID'),
        ];
        return $labels[$key] ?? Inflector::humanize(str_replace('-', '_', $key));
    }
    const FACT_FALLBACK_ROWS = 4;
    const VALUE_LIMIT = 6;
    const REF_LIMIT = 3;
    const RELATED_LIMIT = 5;
    const LATEST_LIMIT = 5;
    const ACTIVITY_MONTHS = 12;
    const ACTIVITY_ROW_CAP = 100000;

    protected function railCardUrl()
    {
        return '/galaxy_clusters/railCard/';
    }

    protected function lazyCards()
    {
        return [
            'cluster-activity' => ['activity', __('Activity'), 'fas fa-chart-column', 'activity'],
            'cluster-latest' => ['list', __('Latest events'), 'misp-icon misp-icon-event misp-simple', 'latest'],
        ];
    }

    /**
     * @param array $cluster
     * @return array
     */
    public function facts(array $cluster)
    {
        $byKey = [];
        foreach ($cluster['GalaxyCluster']['GalaxyElement'] ?? [] as $element) {
            $byKey[$element['key']][] = $element['value'];
        }
        $keys = array_values(array_intersect(self::FACT_KEYS, array_keys($byKey)));
        if (empty($keys)) {
            $others = array_diff(array_keys($byKey), ['refs']);
            $keys = array_slice(array_values($others), 0, self::FACT_FALLBACK_ROWS);
        }
        $rows = [];
        foreach ($keys as $key) {
            $values = array_values(array_unique($byKey[$key]));
            $rows[] = [
                'label' => $this->factLabel($key),
                'values' => array_map(function ($v) use ($key) {
                    return ['text' => $key === 'attribution-confidence' && is_numeric($v) ? $v . '%' : (string)$v];
                }, array_slice($values, 0, self::VALUE_LIMIT)),
                'more' => max(0, count($values) - self::VALUE_LIMIT),
            ];
        }
        $refs = [];
        foreach ($byKey['refs'] ?? [] as $url) {
            $host = preg_match('#^https?://#i', $url) ? parse_url($url, PHP_URL_HOST) : null;
            if ($host) {
                $refs += [$host => $url];
            }
        }
        $refs = array_values($refs);
        if (!empty($refs)) {
            $rows[] = [
                'label' => __('References'),
                'values' => array_map(function ($url) {
                    return ['text' => parse_url($url, PHP_URL_HOST) ?: $url, 'href' => $url];
                }, array_slice($refs, 0, self::REF_LIMIT)),
                'more' => max(0, count($refs) - self::REF_LIMIT),
            ];
        }
        return RailCard::facts(
            'cluster-facts',
            __('Key facts'),
            'fas fa-circle-info',
            $rows,
            [
                'link' => ['label' => __('Elements'), 'href' => '#tab-elements'],
                'empty' => __('No elements describe this cluster.'),
            ]
        );
    }

    /**
     * Relations by type in each direction, with the related clusters the
     * user can see. A relation whose other end is not visible is not counted.
     *
     * @param array $user
     * @param array $cluster
     * @return array
     */
    public function relations(array $user, array $cluster)
    {
        $GalaxyCluster = ClassRegistry::init('GalaxyCluster');
        $edges = [];
        foreach ($cluster['GalaxyCluster']['GalaxyClusterRelation'] ?? [] as $relation) {
            $edges[] = ['out', $relation['referenced_galaxy_cluster_type'], (int)$relation['referenced_galaxy_cluster_id']];
        }
        foreach ($cluster['GalaxyCluster']['TargetingClusterRelation'] ?? [] as $relation) {
            $edges[] = ['in', $relation['referenced_galaxy_cluster_type'], (int)$relation['galaxy_cluster_id']];
        }
        $otherIds = array_values(array_unique(array_filter(array_column($edges, 2))));
        $visible = [];
        if (!empty($otherIds)) {
            $rows = $GalaxyCluster->fetchGalaxyClusters($user, [
                'conditions' => ['GalaxyCluster.id' => $otherIds],
                'fields' => ['GalaxyCluster.id', 'GalaxyCluster.value', 'GalaxyCluster.galaxy_id'],
                'contain' => ['Galaxy' => ['fields' => ['Galaxy.name']]],
            ]);
            foreach ($rows as $row) {
                $visible[(int)$row['GalaxyCluster']['id']] = [
                    'value' => $row['GalaxyCluster']['value'],
                    'galaxy' => $row['Galaxy']['name'] ?? null,
                ];
            }
        }
        $groups = [];
        $total = 0;
        foreach ($edges as list($direction, $type, $otherId)) {
            if (!isset($visible[$otherId])) {
                continue;
            }
            $key = $direction . ':' . $type;
            if (!isset($groups[$key])) {
                $groups[$key] = [
                    'key' => $key,
                    'label' => $direction === 'out' ? $type : __('%s (inbound)', $type),
                    'icon' => $direction === 'out' ? 'fas fa-arrow-right' : 'fas fa-arrow-left',
                    'count' => 0,
                    'others' => [],
                ];
            }
            $groups[$key]['count']++;
            $groups[$key]['others'][$otherId] = true;
            $total++;
        }
        uasort($groups, function ($a, $b) {
            return $b['count'] <=> $a['count'];
        });
        foreach ($groups as $key => $group) {
            $ids = array_keys($group['others']);
            $facets = [];
            foreach (array_slice($ids, 0, self::RELATED_LIMIT) as $otherId) {
                $facets[] = [
                    'label' => $visible[$otherId]['value'],
                    'href' => '/galaxy_clusters/view/' . $otherId,
                ];
            }
            unset($groups[$key]['others']);
            $groups[$key]['facets'] = $facets;
            $groups[$key]['more'] = max(0, count($ids) - self::RELATED_LIMIT);
        }
        return RailCard::inventory(
            'cluster-relations',
            __('Relations'),
            'fas fa-diagram-project',
            ['count' => $total, 'label' => __n('relation', 'relations', $total)],
            array_values($groups),
            true,
            [
                'link' => ['label' => __('Relations'), 'href' => '#tab-relations'],
                'empty' => __('Not related to any other cluster.'),
            ]
        );
    }

    /**
     * The newest events the user can see that carry the cluster's tag.
     *
     * @param array $user
     * @param array $cluster
     * @return array
     */
    public function latest(array $user, array $cluster)
    {
        $tagId = $cluster['GalaxyCluster']['tag_id'] ?? null;
        $rows = [];
        $count = 0;
        if (!empty($tagId)) {
            $EventTag = ClassRegistry::init('EventTag');
            $conditions = $EventTag->Event->createEventConditions($user);
            $conditions['AND'][] = ['EventTag.tag_id' => $tagId];
            $eventIds = $EventTag->find('column', [
                'recursive' => -1,
                'contain' => ['Event'],
                'fields' => ['EventTag.event_id'],
                'conditions' => $conditions,
                'order' => ['Event.date' => 'DESC', 'Event.id' => 'DESC'],
                'limit' => self::LATEST_LIMIT,
            ]);
            if (!empty($eventIds)) {
                $events = $EventTag->Event->find('all', [
                    'recursive' => -1,
                    'conditions' => ['Event.id' => $eventIds],
                    'fields' => ['Event.id', 'Event.info', 'Event.date', 'Event.published'],
                    'contain' => ['Orgc' => ['fields' => ['Orgc.id', 'Orgc.name']]],
                    'order' => ['Event.date' => 'DESC', 'Event.id' => 'DESC'],
                ]);
                foreach ($events as $event) {
                    $rows[] = [
                        'label' => $event['Event']['info'],
                        'href' => '/events/view/' . $event['Event']['id'],
                        'icon' => 'misp-icon misp-icon-event misp-simple',
                        'meta' => [$event['Orgc']['name'] ?? '', $event['Event']['date']],
                        'badge' => $event['Event']['published']
                            ? null
                            : ['label' => __('Unpublished'), 'tone' => 'muted'],
                    ];
                }
            }
            $count = $EventTag->countForTag($tagId, $user);
        }
        list(, $title, $icon) = $this->head('cluster-latest');
        return RailCard::rows(
            'cluster-latest',
            $title,
            $icon,
            $rows,
            $count > count($rows)
                ? ['label' => __n('All %s event', 'All %s events', $count, $count), 'href' => '/events/index/searchtag:' . $tagId]
                : null,
            ['empty' => __('No event carries this cluster.'), 'lazy' => true]
        );
    }

    /**
     * Visible events tagged with the cluster, per month of their event date.
     *
     * @param array $user
     * @param array $cluster
     * @return array
     */
    public function activity(array $user, array $cluster)
    {
        $tagId = $cluster['GalaxyCluster']['tag_id'] ?? null;
        $perMonth = [];
        $latest = null;
        $capped = false;
        if (!empty($tagId)) {
            $EventTag = ClassRegistry::init('EventTag');
            $since = (new DateTime('first day of this month'))
                ->modify('-' . (self::ACTIVITY_MONTHS - 1) . ' months')
                ->format('Y-m-d');
            $conditions = $EventTag->Event->createEventConditions($user);
            $conditions['AND'][] = ['EventTag.tag_id' => $tagId, 'Event.date >=' => $since, 'Event.date <=' => date('Y-m-d')];
            $dates = $EventTag->find('column', [
                'recursive' => -1,
                'contain' => ['Event'],
                'fields' => ['Event.date'],
                'conditions' => $conditions,
                'limit' => self::ACTIVITY_ROW_CAP,
            ]);
            $capped = count($dates) >= self::ACTIVITY_ROW_CAP;
            foreach ($dates as $date) {
                $month = substr($date, 0, 7);
                $perMonth[$month] = ($perMonth[$month] ?? 0) + 1;
                if ($latest === null || $date > $latest) {
                    $latest = $date;
                }
            }
        }
        $series = RailCard::series($perMonth, 'month', self::ACTIVITY_MONTHS);
        $total = array_sum(array_column($series, 'count'));
        list(, $title, $icon) = $this->head('cluster-activity');
        return RailCard::activity(
            'cluster-activity',
            $title,
            $icon,
            'month',
            $series,
            ['count' => $total, 'label' => __n('event in 12 months', 'events in 12 months', $total)],
            $latest === null ? null : RailCard::last(strtotime($latest), __('Latest event')),
            [],
            [
                'empty' => __('No event in the last 12 months.'),
                'lazy' => true,
                'note' => $capped ? __('Counted over the first %s events.', self::ACTIVITY_ROW_CAP) : null,
            ]
        );
    }
}
