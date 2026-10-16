<?php
App::uses('LazyRailCards', 'Tools/RailCards');

/**
 * Rail cards for a galaxy. $galaxy is ['Galaxy' => [...]] with
 * kill_chain_order decoded, as GalaxiesController::view loads it.
 */
class GalaxyRailCards extends LazyRailCards
{
    const USAGE_LIMIT = 10;
    const CONTRIBUTOR_LIMIT = 3;

    protected function railCardUrl()
    {
        return '/galaxies/railCard/';
    }

    protected function lazyCards()
    {
        return [
            'galaxy-usage' => ['list', __('Most used'), 'fas fa-ranking-star', 'usage'],
        ];
    }

    /**
     * @param array $user
     * @param int $galaxyId
     * @return array conditions on GalaxyCluster for the galaxy's visible clusters
     */
    private function clusterConditions(array $user, $galaxyId)
    {
        $conditions = ClassRegistry::init('GalaxyCluster')->buildConditions($user);
        $conditions['AND'][] = ['GalaxyCluster.galaxy_id' => $galaxyId];
        return $conditions;
    }

    /**
     * Where the clusters come from: shipped or made here, published, deleted,
     * and the organisations that made the most.
     *
     * @param array $user
     * @param array $galaxy
     * @return array
     */
    public function composition(array $user, array $galaxy)
    {
        $GalaxyCluster = ClassRegistry::init('GalaxyCluster');
        $conditions = $this->clusterConditions($user, $galaxy['Galaxy']['id']);
        $rows = $GalaxyCluster->find('all', [
            'recursive' => -1,
            'conditions' => $conditions,
            'fields' => ['GalaxyCluster.default', 'GalaxyCluster.published', 'GalaxyCluster.deleted', 'COUNT(GalaxyCluster.id) AS n'],
            'group' => ['GalaxyCluster.default', 'GalaxyCluster.published', 'GalaxyCluster.deleted'],
        ]);
        $shipped = $local = $published = $deleted = 0;
        foreach ($rows as $row) {
            $c = $row['GalaxyCluster'];
            $n = (int)$row[0]['n'];
            if ($c['deleted']) {
                $deleted += $n;
                continue;
            }
            if ($c['default']) {
                $shipped += $n;
            } else {
                $local += $n;
                $published += $c['published'] ? $n : 0;
            }
        }
        $total = $shipped + $local;
        $groups = [];
        if ($total) {
            $groups[] = [
                'key' => 'origin',
                'label' => __('Origin'),
                'icon' => 'fas fa-box-open',
                'count' => $total,
                'partition' => true,
                'facets' => array_values(array_filter([
                    $shipped ? ['label' => __('Shipped'), 'count' => $shipped] : null,
                    $local ? ['label' => __('Made here'), 'count' => $local] : null,
                ])),
            ];
        }
        if ($local) {
            $groups[] = [
                'key' => 'published',
                'label' => __('Publication'),
                'icon' => 'fas fa-pen-ruler',
                'count' => $local,
                'partition' => true,
                'facets' => array_values(array_filter([
                    $published ? ['label' => __('Published'), 'count' => $published, 'tone' => 'ok'] : null,
                    $local - $published ? ['label' => __('Unpublished'), 'count' => $local - $published, 'tone' => 'muted'] : null,
                ])),
            ];
            $conditions['AND'][] = ['GalaxyCluster.default' => 0, 'GalaxyCluster.deleted' => 0];
            $byOrg = $GalaxyCluster->find('all', [
                'recursive' => -1,
                'conditions' => $conditions,
                'fields' => ['GalaxyCluster.orgc_id', 'COUNT(GalaxyCluster.id) AS n'],
                'group' => ['GalaxyCluster.orgc_id'],
            ]);
            usort($byOrg, function ($a, $b) {
                return (int)$b[0]['n'] <=> (int)$a[0]['n'];
            });
            $names = ClassRegistry::init('Organisation')->find('list', [
                'conditions' => ['Organisation.id' => array_column(array_column($byOrg, 'GalaxyCluster'), 'orgc_id')],
                'fields' => ['Organisation.id', 'Organisation.name'],
            ]);
            $facets = [];
            foreach (array_slice($byOrg, 0, self::CONTRIBUTOR_LIMIT) as $row) {
                $orgId = $row['GalaxyCluster']['orgc_id'];
                $facets[] = [
                    'label' => $names[$orgId] ?? __('Unknown'),
                    'count' => (int)$row[0]['n'],
                    'href' => '/organisations/view/' . $orgId,
                ];
            }
            $groups[] = [
                'key' => 'contributors',
                'label' => __n('%s contributor', '%s contributors', count($byOrg), count($byOrg)),
                'icon' => 'misp-icon misp-icon-organisation misp-simple',
                'count' => $local,
                'partition' => true,
                'facets' => $facets,
                'more' => max(0, count($byOrg) - self::CONTRIBUTOR_LIMIT),
            ];
        }
        return RailCard::inventory(
            'galaxy-composition',
            __('Composition'),
            'fas fa-layer-group',
            ['count' => $total, 'label' => __n('cluster', 'clusters', $total)],
            $groups,
            false,
            [
                'link' => ['label' => __('Clusters'), 'href' => '#tab-clusters'],
                'empty' => __('This galaxy has no cluster.'),
                'note' => $deleted ? __n('%s deleted cluster is not counted.', '%s deleted clusters are not counted.', $deleted, number_format($deleted)) : null,
            ]
        );
    }

    /**
     * The galaxy's clusters carried by the most events the user can see.
     *
     * @param array $user
     * @param array $galaxy
     * @return array
     */
    public function usage(array $user, array $galaxy)
    {
        $clusters = ClassRegistry::init('GalaxyCluster')->find('all', [
            'recursive' => -1,
            'conditions' => $this->clusterConditions($user, $galaxy['Galaxy']['id']) + ['GalaxyCluster.deleted' => 0],
            'fields' => ['GalaxyCluster.id', 'GalaxyCluster.value', 'GalaxyCluster.tag_name'],
        ]);
        $byTagName = [];
        foreach ($clusters as $cluster) {
            $byTagName[$cluster['GalaxyCluster']['tag_name']] = $cluster['GalaxyCluster'];
        }
        $tags = empty($byTagName) ? [] : ClassRegistry::init('Tag')->find('list', [
            'conditions' => ['Tag.name' => array_keys($byTagName)],
            'fields' => ['Tag.id', 'Tag.name'],
        ]);
        $counts = ClassRegistry::init('EventTag')->countForTags(array_keys($tags), $user);
        $counts = array_filter(array_map('intval', $counts));
        arsort($counts);
        $rows = [];
        foreach (array_slice($counts, 0, self::USAGE_LIMIT, true) as $tagId => $count) {
            $cluster = $byTagName[$tags[$tagId]];
            $rows[] = [
                'label' => $cluster['value'],
                'href' => '/galaxy_clusters/view/' . $cluster['id'],
                'count' => $count,
            ];
        }
        list(, $title, $icon) = $this->head('galaxy-usage');
        return RailCard::rows(
            'galaxy-usage',
            $title,
            $icon,
            $rows,
            count($counts) > count($rows)
                ? ['label' => __('%s clusters in use', number_format(count($counts))), 'href' => '#tab-clusters']
                : null,
            ['empty' => __('No event carries a cluster of this galaxy.'), 'lazy' => true]
        );
    }
}
