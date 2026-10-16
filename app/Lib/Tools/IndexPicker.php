<?php

/**
 * Search-as-you-type for index filter pickers: one row shape
 * `{value, label, style}` for organisations, tags and galaxy clusters.
 */
class IndexPicker
{
    const LIMIT = 20;
    const MAX_LIMIT = 200;
    const MIN_TERM = 2;
    const CONTAINS_FROM = 3;
    const SCOPES_TTL = 300;
    const DESCRIPTION_LENGTH = 160;

    /**
     * Prefix matches first; when they leave room and the term is long
     * enough, unordered contains matches fill the rest. An empty term is
     * allowed when $minTerm is 0: the first $limit rows in query order.
     *
     * @param Model $model
     * @param array $query find('all') options without the match condition
     * @param string $field the matched column, e.g. 'LOWER(Tag.name)'
     * @param string $term
     * @param callable $row model row => picker row
     * @param int $limit
     * @param int $minTerm
     * @return array
     */
    public static function search(Model $model, array $query, $field, $term, callable $row, $limit = self::LIMIT, $minTerm = self::MIN_TERM)
    {
        $term = mb_strtolower(trim((string)$term));
        if (mb_strlen($term) < $minTerm) {
            return [];
        }
        $found = [];
        $collect = function (array $rows) use (&$found, $row, $limit) {
            foreach ($rows as $r) {
                $out = $row($r);
                if ($out !== null && !isset($found[$out['value']]) && count($found) < $limit) {
                    $found[$out['value']] = $out;
                }
            }
        };
        if ($term === '') {
            $query['limit'] = $limit;
            $collect($model->find('all', $query));
            return array_values($found);
        }
        $like = addcslashes($term, '%_\\');
        $prefix = $query;
        $prefix['conditions']['AND'][] = [$field . ' LIKE' => $like . '%'];
        $prefix['limit'] = $limit;
        $collect($model->find('all', $prefix));

        if (count($found) < $limit && mb_strlen($term) >= self::CONTAINS_FROM) {
            $contains = $query;
            $contains['conditions']['AND'][] = [$field . ' LIKE' => '%' . $like . '%'];
            $contains['limit'] = $limit;
            $contains['order'] = false;
            $collect($model->find('all', $contains));
        }
        return array_values($found);
    }

    /**
     * @param mixed $limit as given in the request
     * @return int
     */
    public static function limit($limit)
    {
        if ($limit === null || $limit === '' || !is_numeric($limit)) {
            return self::LIMIT;
        }
        return max(1, min(self::MAX_LIMIT, (int)$limit));
    }

    /**
     * @param array $user
     * @return bool whether this reader may pick creator organisations
     */
    public static function canPickOrgs(array $user)
    {
        if (!Configure::read('MISP.showorg')) {
            return false;
        }
        return !Configure::read('Security.hide_organisation_index_from_users')
            || !empty($user['Role']['perm_sharing_group']);
    }

    /**
     * @param array $user
     * @param string $term
     * @return array
     */
    public static function organisations(array $user, $term)
    {
        if (!self::canPickOrgs($user)) {
            return [];
        }
        $Organisation = ClassRegistry::init('Organisation');
        return self::search($Organisation, [
            'conditions' => ['AND' => [$Organisation->createConditions($user)]],
            'fields' => ['Organisation.id', 'Organisation.name', 'Organisation.uuid'],
            'order' => ['Organisation.name' => 'ASC'],
            'recursive' => -1,
        ], 'LOWER(Organisation.name)', $term, [self::class, 'orgRow']);
    }

    /**
     * The org picker's rows before anything is typed: the reader's own org,
     * then the creator orgs of the rows on the page, most frequent first.
     *
     * @param array $user
     * @param array $orgs one Organisation (id, name, uuid) per row on the page
     * @param int $limit
     * @return array groups of {label, rows, more}
     */
    public static function orgSuggestions(array $user, array $orgs, $limit = 10)
    {
        if (!self::canPickOrgs($user)) {
            return [];
        }
        $groups = [];
        $mine = (string)($user['Organisation']['id'] ?? '');
        if ($mine !== '') {
            $row = self::orgRow(['Organisation' => $user['Organisation']]);
            $row['note'] = __('your organisation');
            $groups[] = ['label' => null, 'rows' => [$row], 'more' => 0];
        }
        $counts = [];
        $seen = [];
        foreach ($orgs as $org) {
            $id = (string)($org['id'] ?? '');
            if ($id === '' || $id === $mine) {
                continue;
            }
            $counts[$id] = ($counts[$id] ?? 0) + 1;
            $seen[$id] = $org;
        }
        uksort($counts, function ($a, $b) use ($counts, $seen) {
            return $counts[$b] <=> $counts[$a] ?: strcasecmp($seen[$a]['name'] ?? '', $seen[$b]['name'] ?? '');
        });
        $ids = array_slice(array_keys($counts), 0, $limit);
        if ($ids) {
            $groups[] = [
                'label' => __('On this page'),
                'rows' => array_map(function ($id) use ($seen) {
                    return self::orgRow(['Organisation' => $seen[$id]]);
                }, $ids),
                'more' => count($counts) - count($ids),
            ];
        }
        return $groups;
    }

    /**
     * @param array $user
     * @param string $term
     * @param array $options scope (a namespace, `-` for none), predicate, limit
     * @return array
     */
    public static function tags(array $user, $term, array $options = [])
    {
        $Tag = ClassRegistry::init('Tag');
        $conditions = [
            $Tag->createConditions($user),
            ['Tag.hide_tag' => 0, 'Tag.is_galaxy' => 0],
        ];
        $scope = trim((string)($options['scope'] ?? ''));
        if ($scope !== '') {
            $conditions[] = self::namespaceCondition($scope, $options['predicate'] ?? null);
        }
        $rows = self::search($Tag, [
            'conditions' => ['AND' => $conditions],
            'fields' => ['Tag.name', 'Tag.colour'],
            'order' => ['Tag.name' => 'ASC'],
            'recursive' => -1,
        ], 'Tag.name', $term, [self::class, 'tagRow'], self::limit($options['limit'] ?? null), $scope === '' ? self::MIN_TERM : 0);
        return self::withTaxonomy($rows);
    }

    /**
     * @param string $namespace `-` for tags with no namespace
     * @param string|null $predicate
     * @return array
     */
    private static function namespaceCondition($namespace, $predicate)
    {
        if ($namespace === '-') {
            return ['Tag.name NOT LIKE' => '_%:%'];
        }
        $head = addcslashes($namespace, '%_\\') . ':';
        $predicate = trim((string)$predicate);
        if ($predicate === '') {
            return ['Tag.name LIKE' => $head . '%'];
        }
        return ['OR' => [
            ['Tag.name' => $namespace . ':' . $predicate],
            ['Tag.name LIKE' => $head . addcslashes($predicate, '%_\\') . '=%'],
        ]];
    }

    /**
     * Adds what a taxonomy says about each tag that is one of its entries.
     *
     * @param array $rows tag picker rows
     * @return array
     */
    private static function withTaxonomy(array $rows)
    {
        $wanted = [];
        foreach ($rows as $row) {
            $parts = self::tagParts($row['value']);
            if ($parts !== null) {
                $wanted[$parts['namespace']][$parts['predicate']] = true;
            }
        }
        if (empty($wanted)) {
            return $rows;
        }
        $Taxonomy = ClassRegistry::init('Taxonomy');
        $taxonomies = $Taxonomy->find('list', [
            'conditions' => ['LOWER(Taxonomy.namespace)' => array_map('strval', array_keys($wanted))],
            'fields' => ['Taxonomy.id', 'Taxonomy.namespace'],
            'recursive' => -1,
        ]);
        if (empty($taxonomies)) {
            return $rows;
        }
        $predicates = [];
        foreach ($taxonomies as $id => $namespace) {
            $ns = mb_strtolower($namespace);
            if (empty($wanted[$ns])) {
                continue;
            }
            $found = $Taxonomy->TaxonomyPredicate->find('all', [
                'conditions' => [
                    'TaxonomyPredicate.taxonomy_id' => $id,
                    'LOWER(TaxonomyPredicate.value)' => array_map('strval', array_keys($wanted[$ns])),
                ],
                'contain' => ['TaxonomyEntry'],
            ]);
            foreach ($found as $p) {
                $predicates[$ns][mb_strtolower($p['TaxonomyPredicate']['value'])] = $p;
            }
        }
        foreach ($rows as &$row) {
            $parts = self::tagParts($row['value']);
            $p = $parts === null ? null : ($predicates[$parts['namespace']][$parts['predicate']] ?? null);
            if ($p === null) {
                continue;
            }
            $entry = null;
            if ($parts['value'] !== null) {
                foreach ($p['TaxonomyEntry'] as $e) {
                    if (mb_strtolower($e['value']) === $parts['value']) {
                        $entry = $e;
                        break;
                    }
                }
                if ($entry === null) {
                    continue;
                }
            } elseif (!empty($p['TaxonomyEntry'])) {
                continue;
            }
            $predicateExpanded = $p['TaxonomyPredicate']['expanded'] ?: $p['TaxonomyPredicate']['value'];
            $row['taxonomy'] = [
                'namespace' => $taxonomies[$p['TaxonomyPredicate']['taxonomy_id']],
                'predicate' => $p['TaxonomyPredicate']['value'],
                'predicate_expanded' => $predicateExpanded,
                'entry' => $entry ? $entry['value'] : null,
                'expanded' => $entry ? ($entry['expanded'] ?: $entry['value']) : $predicateExpanded,
                'numerical_value' => $entry ? $entry['numerical_value'] : $p['TaxonomyPredicate']['numerical_value'],
            ];
        }
        return $rows;
    }

    /**
     * `ns:predicate` or `ns:predicate="value"`, lowercased; predicates may
     * hold colons themselves (veris `asset:country`).
     *
     * @param string $name
     * @return array|null
     */
    private static function tagParts($name)
    {
        $i = strpos($name, ':');
        if ($i === false || $i === 0) {
            return null;
        }
        $rest = substr($name, $i + 1);
        $value = null;
        if (preg_match('/^(.+?)="(.*)"$/s', $rest, $m)) {
            $rest = $m[1];
            $value = mb_strtolower($m[2]);
        }
        return [
            'namespace' => mb_strtolower(substr($name, 0, $i)),
            'predicate' => mb_strtolower($rest),
            'value' => $value,
        ];
    }

    /**
     * What the Tag picker can narrow to: taxonomies (enabled, or with tags
     * here), tag namespaces with no taxonomy behind them, and how many tags
     * carry no namespace. Sizes are rows in `tags`, never event counts.
     *
     * @param array $user
     * @return array
     */
    public static function tagScopes(array $user)
    {
        $counts = self::namespaceCounts($user);
        $plan = self::plan($user);
        $Taxonomy = ClassRegistry::init('Taxonomy');
        $rows = $Taxonomy->find('all', [
            'fields' => ['Taxonomy.namespace', 'Taxonomy.description', 'Taxonomy.enabled', 'Taxonomy.exclusive'],
            'order' => ['Taxonomy.namespace' => 'ASC'],
            'recursive' => -1,
        ]);
        $taxonomies = [];
        $covered = [];
        foreach ($rows as $r) {
            $t = $r['Taxonomy'];
            $ns = mb_strtolower($t['namespace']);
            $tags = $counts['namespaces'][$ns][1] ?? 0;
            if (!$t['enabled'] && !$tags) {
                continue;
            }
            $covered[$ns] = true;
            $taxonomies[] = [
                'namespace' => $t['namespace'],
                'description' => $t['description'],
                'enabled' => (bool)$t['enabled'],
                'exclusive' => (bool)$t['exclusive'],
                'tags' => $tags,
                'pinned' => self::rank($plan, 'taxonomies', 'pinned', $ns),
                'preferred' => self::rank($plan, 'taxonomies', 'preferred', $ns),
            ];
        }
        $namespaces = [];
        foreach ($counts['namespaces'] as $ns => $entry) {
            if (isset($covered[$ns]) || $ns === 'misp-galaxy') {
                continue;
            }
            $namespaces[] = ['namespace' => $entry[0], 'tags' => $entry[1]];
        }
        return [
            'taxonomies' => $taxonomies,
            'namespaces' => $namespaces,
            'no_namespace' => $counts['none'],
        ];
    }

    /**
     * Tags per namespace the reader may see, cached for a few minutes: on
     * feed-heavy instances this is a scan of the whole `tags` table.
     *
     * @param array $user
     * @return array {namespaces: lowercased ns => [as written, count], none: count}
     */
    private static function namespaceCounts(array $user)
    {
        $key = 'misp:index_picker:tag_namespaces:' . self::cacheScope($user);
        $cached = self::cacheGet($key);
        if ($cached !== null) {
            return $cached;
        }
        $Tag = ClassRegistry::init('Tag');
        $base = [$Tag->createConditions($user), ['Tag.hide_tag' => 0, 'Tag.is_galaxy' => 0]];
        $rows = $Tag->find('all', [
            'fields' => ["SUBSTRING_INDEX(Tag.name, ':', 1) AS ns", 'COUNT(*) AS n'],
            'conditions' => ['AND' => array_merge($base, [['Tag.name LIKE' => '_%:%']])],
            'group' => ['ns'],
            'recursive' => -1,
        ]);
        $namespaces = [];
        foreach ($rows as $r) {
            $ns = trim($r[0]['ns']);
            if ($ns === '') {
                continue;
            }
            $lower = mb_strtolower($ns);
            if (isset($namespaces[$lower])) {
                $namespaces[$lower][1] += (int)$r[0]['n'];
            } else {
                $namespaces[$lower] = [$ns, (int)$r[0]['n']];
            }
        }
        uasort($namespaces, function ($a, $b) {
            return $b[1] - $a[1];
        });
        $none = $Tag->find('count', [
            'conditions' => ['AND' => array_merge($base, [self::namespaceCondition('-', null)])],
            'recursive' => -1,
        ]);
        $counts = ['namespaces' => $namespaces, 'none' => $none];
        self::cacheSet($key, $counts);
        return $counts;
    }

    /**
     * One taxonomy's predicates and entries, each with its tag name and
     * whether that tag exists for the reader.
     *
     * @param array $user
     * @param string $namespace
     * @return array|null
     */
    public static function taxonomyTree(array $user, $namespace)
    {
        $Taxonomy = ClassRegistry::init('Taxonomy');
        $taxonomy = $Taxonomy->find('first', [
            'conditions' => ['LOWER(Taxonomy.namespace)' => mb_strtolower(trim((string)$namespace))],
            'fields' => ['Taxonomy.id', 'Taxonomy.namespace', 'Taxonomy.description', 'Taxonomy.exclusive'],
            'recursive' => -1,
        ]);
        if (empty($taxonomy)) {
            return null;
        }
        $ns = $taxonomy['Taxonomy']['namespace'];
        $found = $Taxonomy->TaxonomyPredicate->find('all', [
            'conditions' => ['TaxonomyPredicate.taxonomy_id' => $taxonomy['Taxonomy']['id']],
            'contain' => ['TaxonomyEntry'],
            'order' => ['TaxonomyPredicate.id' => 'ASC'],
        ]);
        $names = [];
        foreach ($found as $p) {
            $names[] = $ns . ':' . $p['TaxonomyPredicate']['value'];
            foreach ($p['TaxonomyEntry'] as $e) {
                $names[] = $ns . ':' . $p['TaxonomyPredicate']['value'] . '="' . $e['value'] . '"';
            }
        }
        $existing = self::existingTags($user, $names);
        $predicates = [];
        foreach ($found as $p) {
            $pv = $p['TaxonomyPredicate']['value'];
            $entries = [];
            foreach ($p['TaxonomyEntry'] as $e) {
                $tag = $ns . ':' . $pv . '="' . $e['value'] . '"';
                $live = $existing[mb_strtolower($tag)] ?? null;
                $entries[] = [
                    'value' => $e['value'],
                    'expanded' => $e['expanded'],
                    'description' => $e['description'] ?? null,
                    'colour' => $e['colour'] ?: ($live ?: null),
                    'numerical_value' => $e['numerical_value'],
                    'tag' => $tag,
                    'tag_exists' => $live !== null,
                ];
            }
            $tag = $ns . ':' . $pv;
            $live = $existing[mb_strtolower($tag)] ?? null;
            $predicates[] = [
                'value' => $pv,
                'expanded' => $p['TaxonomyPredicate']['expanded'],
                'description' => $p['TaxonomyPredicate']['description'] ?? null,
                'colour' => $p['TaxonomyPredicate']['colour'] ?: ($live ?: null),
                'exclusive' => !empty($p['TaxonomyPredicate']['exclusive']),
                'tag' => $entries ? null : $tag,
                'tag_exists' => $entries ? null : $live !== null,
                'entries' => $entries,
            ];
        }
        return [
            'namespace' => $ns,
            'description' => $taxonomy['Taxonomy']['description'],
            'exclusive' => (bool)$taxonomy['Taxonomy']['exclusive'],
            'predicates' => $predicates,
        ];
    }

    /**
     * @param array $user
     * @param array $names
     * @return array lowercased name => colour ('' when none), for the tags the reader may see
     */
    private static function existingTags(array $user, array $names)
    {
        if (empty($names)) {
            return [];
        }
        $Tag = ClassRegistry::init('Tag');
        $out = [];
        foreach (array_chunk($names, 1000) as $chunk) {
            $rows = $Tag->find('list', [
                'conditions' => ['AND' => [
                    $Tag->createConditions($user),
                    ['Tag.hide_tag' => 0, 'Tag.name' => $chunk],
                ]],
                'fields' => ['Tag.name', 'Tag.colour'],
                'recursive' => -1,
            ]);
            foreach ($rows as $name => $colour) {
                $out[mb_strtolower($name)] = (string)$colour;
            }
        }
        return $out;
    }

    /**
     * What the Galaxy picker can narrow to: the galaxies with clusters the
     * reader may see. `clusters` and `in_use` (clusters whose tag exists)
     * are rows in the galaxy tables, never event counts.
     *
     * @param array $user
     * @return array
     */
    public static function galaxyScopes(array $user)
    {
        $counts = self::clusterCounts($user);
        $plan = self::plan($user);
        $Galaxy = ClassRegistry::init('Galaxy');
        $rows = $Galaxy->find('all', [
            'conditions' => $Galaxy->buildConditions($user),
            'fields' => ['Galaxy.id', 'Galaxy.type', 'Galaxy.name', 'Galaxy.namespace', 'Galaxy.icon', 'Galaxy.description', 'Galaxy.kill_chain_order', 'Galaxy.default'],
            'order' => ['Galaxy.name' => 'ASC'],
            'recursive' => -1,
        ]);
        $out = [];
        foreach ($rows as $r) {
            $g = $r['Galaxy'];
            if (empty($counts[$g['id']])) {
                continue;
            }
            $order = null;
            $tactics = null;
            if (!empty($g['kill_chain_order'])) {
                $order = is_array($g['kill_chain_order']) ? $g['kill_chain_order'] : json_decode($g['kill_chain_order'], true);
                if (is_array($order)) {
                    $tactics = [];
                    foreach ($order as $matrix) {
                        foreach ((array)$matrix as $tactic) {
                            if (!in_array($tactic, $tactics, true)) {
                                $tactics[] = $tactic;
                            }
                        }
                    }
                } else {
                    $order = null;
                }
            }
            $type = mb_strtolower($g['type']);
            $out[] = [
                'type' => $g['type'],
                'name' => $g['name'],
                'namespace' => $g['namespace'],
                'icon' => self::iconClass($g['icon']),
                'description' => $g['description'],
                'clusters' => $counts[$g['id']][0],
                'in_use' => $counts[$g['id']][1],
                'kill_chain' => $tactics,
                'kill_chain_order' => $order,
                'preferred' => self::rank($plan, 'galaxies', 'preferred', $type),
                'pinned' => self::rank($plan, 'galaxies', 'pinned', $type),
                'default' => (bool)$g['default'],
            ];
        }
        return $out;
    }

    /**
     * Clusters are counted by tag name, as the search lists them.
     *
     * @param array $user
     * @return array galaxy id => [clusters, clusters whose tag exists]
     */
    private static function clusterCounts(array $user)
    {
        $key = 'misp:index_picker:cluster_counts:' . self::cacheScope($user);
        $cached = self::cacheGet($key);
        if ($cached !== null) {
            return $cached;
        }
        $GalaxyCluster = ClassRegistry::init('GalaxyCluster');
        $conditions = ['AND' => [$GalaxyCluster->buildConditions($user), ['GalaxyCluster.deleted' => 0]]];
        $count = function (array $conditions) use ($GalaxyCluster) {
            $rows = $GalaxyCluster->find('all', [
                'fields' => ['GalaxyCluster.galaxy_id', 'COUNT(DISTINCT GalaxyCluster.tag_name) AS n'],
                'conditions' => $conditions,
                'group' => ['GalaxyCluster.galaxy_id'],
                'recursive' => -1,
            ]);
            $out = [];
            foreach ($rows as $r) {
                $out[$r['GalaxyCluster']['galaxy_id']] = (int)$r[0]['n'];
            }
            return $out;
        };
        $all = $count($conditions);
        $inUse = $count(self::withInUse($conditions, $user));
        $counts = [];
        foreach ($all as $id => $n) {
            $counts[$id] = [$n, $inUse[$id] ?? 0];
        }
        self::cacheSet($key, $counts);
        return $counts;
    }

    /**
     * @param array $conditions
     * @param array $user
     * @return array the same, restricted to clusters attached somewhere (their tag exists for the reader)
     */
    private static function withInUse(array $conditions, array $user)
    {
        $acl = '';
        if (empty($user['Role']['perm_site_admin'])) {
            $acl = sprintf(
                ' AND InUseTag.org_id IN (0, %d) AND InUseTag.user_id IN (0, %d)',
                $user['org_id'],
                $user['id']
            );
        }
        $conditions['AND'][] = 'EXISTS (SELECT 1 FROM tags AS InUseTag WHERE InUseTag.name = GalaxyCluster.tag_name AND InUseTag.hide_tag = 0' . $acl . ')';
        return $conditions;
    }

    /**
     * @param array $user
     * @param string $term
     * @param string $valueField 'tag_name', or 'uuid' to name one cluster among same-named ones
     * @param array $options galaxy (type), kill_chain (tactic or matrix:tactic), in_use, limit
     * @return array
     */
    public static function clusters(array $user, $term, $valueField = 'tag_name', array $options = [])
    {
        $GalaxyCluster = ClassRegistry::init('GalaxyCluster');
        $conditions = ['AND' => [
            $GalaxyCluster->buildConditions($user),
            ['GalaxyCluster.deleted' => 0],
        ]];
        $limit = self::limit($options['limit'] ?? null);
        $galaxyId = null;
        $type = trim((string)($options['galaxy'] ?? ''));
        if ($type !== '') {
            $Galaxy = ClassRegistry::init('Galaxy');
            $galaxy = $Galaxy->find('first', [
                'conditions' => ['AND' => [$Galaxy->buildConditions($user), ['Galaxy.type' => $type]]],
                'fields' => ['Galaxy.id'],
                'recursive' => -1,
            ]);
            if (empty($galaxy)) {
                return [];
            }
            $galaxyId = (int)$galaxy['Galaxy']['id'];
            $conditions['AND'][] = ['GalaxyCluster.galaxy_id' => $galaxyId];
            $tactic = trim((string)($options['kill_chain'] ?? ''));
            if ($tactic !== '') {
                $ids = self::clusterIdsByElement($galaxyId, 'kill_chain', $tactic, false);
                if (empty($ids)) {
                    return [];
                }
                $conditions['AND'][] = ['GalaxyCluster.id' => array_keys($ids)];
            }
        }
        if (!empty($options['in_use'])) {
            $conditions = self::withInUse($conditions, $user);
        }
        $query = [
            'conditions' => $conditions,
            'fields' => ['GalaxyCluster.value', 'GalaxyCluster.tag_name', 'GalaxyCluster.uuid', 'GalaxyCluster.description', 'GalaxyCluster.default', 'Galaxy.name', 'Galaxy.icon', 'Galaxy.type'],
            'contain' => ['Galaxy'],
            'order' => ['GalaxyCluster.value' => 'ASC'],
        ];
        $toRow = function (array $r) use ($valueField) {
            $row = self::clusterRow($r);
            $row['value'] = $r['GalaxyCluster'][$valueField];
            return $row;
        };
        $rows = self::search($GalaxyCluster, $query, 'LOWER(GalaxyCluster.value)', $term, $toRow, $limit, $galaxyId === null ? self::MIN_TERM : 0);

        $term = mb_strtolower(trim((string)$term));
        if ($galaxyId !== null && count($rows) < $limit && mb_strlen($term) >= self::MIN_TERM) {
            $synonyms = self::clusterIdsByElement($galaxyId, 'synonyms', $term, true);
            if (!empty($synonyms)) {
                $query['conditions']['AND'][] = ['GalaxyCluster.id' => array_keys($synonyms)];
                $query['fields'][] = 'GalaxyCluster.id';
                $have = array_flip(array_column($rows, 'value'));
                foreach ($GalaxyCluster->find('all', $query) as $r) {
                    $row = $toRow($r);
                    if (isset($have[$row['value']]) || count($rows) >= $limit) {
                        continue;
                    }
                    $have[$row['value']] = true;
                    $row['matched_synonym'] = $synonyms[$r['GalaxyCluster']['id']];
                    $rows[] = $row;
                }
            }
        }
        return self::withInUseFlag($user, $rows, $valueField);
    }

    /**
     * Clusters of one galaxy carrying a galaxy element: a kill chain tactic
     * (`initial-access` matches any matrix, `matrix:tactic` one), or a
     * synonym containing the term.
     *
     * @param int $galaxyId
     * @param string $key
     * @param string $value
     * @param bool $contains
     * @return array cluster id => the element's value
     */
    private static function clusterIdsByElement($galaxyId, $key, $value, $contains)
    {
        $like = addcslashes(mb_strtolower($value), '%_\\');
        if ($contains) {
            $match = ['LOWER(GalaxyElement.value) LIKE' => '%' . $like . '%'];
        } elseif (strpos($value, ':') !== false) {
            $match = ['GalaxyElement.value' => $value];
        } else {
            $match = ['GalaxyElement.value LIKE' => '%:' . addcslashes($value, '%_\\')];
        }
        $GalaxyElement = ClassRegistry::init('GalaxyElement');
        $rows = $GalaxyElement->find('all', [
            'conditions' => ['AND' => [
                ['GalaxyElement.key' => $key],
                $match,
                ['GalaxyCluster.galaxy_id' => $galaxyId],
            ]],
            'fields' => ['GalaxyElement.galaxy_cluster_id', 'GalaxyElement.value'],
            'joins' => [[
                'table' => 'galaxy_clusters',
                'alias' => 'GalaxyCluster',
                'type' => 'INNER',
                'conditions' => ['GalaxyCluster.id = GalaxyElement.galaxy_cluster_id'],
            ]],
            'recursive' => -1,
        ]);
        $out = [];
        foreach ($rows as $r) {
            $id = $r['GalaxyElement']['galaxy_cluster_id'];
            if (!isset($out[$id])) {
                $out[$id] = $r['GalaxyElement']['value'];
            }
        }
        return $out;
    }

    /**
     * @param array $user
     * @param array $rows cluster picker rows
     * @param string $valueField
     * @return array the rows, each with `in_use`: whether its tag exists
     */
    private static function withInUseFlag(array $user, array $rows, $valueField)
    {
        if (empty($rows)) {
            return $rows;
        }
        $names = array_values(array_filter(array_column($rows, 'tag_name')));
        $existing = self::existingTags($user, $names);
        foreach ($rows as &$row) {
            $row['in_use'] = isset($existing[mb_strtolower((string)$row['tag_name'])]);
            if ($valueField !== 'tag_name') {
                continue;
            }
            unset($row['tag_name']);
        }
        return $rows;
    }

    /**
     * The sharing groups the reader may see, by name; the picker narrows the
     * whole list itself.
     *
     * @param array $user
     * @param array|null $ids only these
     * @return array
     */
    public static function sharingGroups(array $user, $ids = null)
    {
        $SharingGroup = ClassRegistry::init('SharingGroup');
        $authorised = array_diff($SharingGroup->authorizedIds($user), [-1]);
        if ($ids !== null) {
            $authorised = array_intersect($authorised, array_map('intval', $ids));
        }
        if (empty($authorised)) {
            return [];
        }
        $rows = $SharingGroup->find('all', [
            'conditions' => ['SharingGroup.id' => array_values($authorised)],
            'fields' => ['SharingGroup.id', 'SharingGroup.name', 'SharingGroup.active'],
            'order' => ['SharingGroup.name' => 'ASC'],
            'recursive' => -1,
        ]);
        return array_map(function (array $r) {
            return [
                'value' => (string)$r['SharingGroup']['id'],
                'label' => $r['SharingGroup']['name'],
                'note' => $r['SharingGroup']['active'] ? null : __('inactive'),
            ];
        }, $rows);
    }

    /**
     * The chips' labels for the values a URL carries, under the same ACL as
     * the searches; a value the reader may not resolve stays as given.
     *
     * @param array $user
     * @param array $values kind (org, tag, galaxy, sharinggroup) => raw values, `!` stripped
     * @return array kind => value => {value, label, style}
     */
    public static function resolve(array $user, array $values)
    {
        $out = ['org' => [], 'tag' => [], 'galaxy' => [], 'sharinggroup' => []];
        $sharingGroups = array_values(array_filter($values['sharinggroup'] ?? [], 'is_numeric'));
        if ($sharingGroups) {
            $out['sharinggroup'] = array_column(self::sharingGroups($user, $sharingGroups), null, 'value');
        }
        $orgs = array_values(array_filter($values['org'] ?? [], 'is_numeric'));
        if ($orgs && self::canPickOrgs($user)) {
            $Organisation = ClassRegistry::init('Organisation');
            $rows = $Organisation->find('all', [
                'conditions' => ['AND' => [$Organisation->createConditions($user), ['Organisation.id' => $orgs]]],
                'fields' => ['Organisation.id', 'Organisation.name', 'Organisation.uuid'],
                'recursive' => -1,
            ]);
            foreach ($rows as $r) {
                $out['org'][(string)$r['Organisation']['id']] = self::orgRow($r);
            }
        }
        if (!empty($values['tag'])) {
            $Tag = ClassRegistry::init('Tag');
            $rows = $Tag->find('all', [
                'conditions' => ['AND' => [$Tag->createConditions($user), ['Tag.name' => $values['tag']]]],
                'fields' => ['Tag.name', 'Tag.colour'],
                'recursive' => -1,
            ]);
            foreach ($rows as $r) {
                $out['tag'][$r['Tag']['name']] = self::tagRow($r);
            }
        }
        if (!empty($values['galaxy'])) {
            $GalaxyCluster = ClassRegistry::init('GalaxyCluster');
            $rows = $GalaxyCluster->find('all', [
                'conditions' => ['AND' => [
                    $GalaxyCluster->buildConditions($user),
                    ['GalaxyCluster.tag_name' => $values['galaxy'], 'GalaxyCluster.deleted' => 0],
                ]],
                'fields' => ['GalaxyCluster.value', 'GalaxyCluster.tag_name', 'Galaxy.name', 'Galaxy.icon'],
                'contain' => ['Galaxy'],
            ]);
            foreach ($rows as $r) {
                $out['galaxy'][$r['GalaxyCluster']['tag_name']] = self::clusterRow($r);
            }
        }
        return $out;
    }

    /**
     * The org's logo when it has one, else the monogram the events index
     * draws for it.
     */
    public static function orgRow(array $r)
    {
        App::uses('OrgImgHelper', 'View/Helper');
        App::uses('EventCardTool', 'Tools/EventOverview');
        $org = $r['Organisation'];
        if (OrgImgHelper::imageFile($org) !== null) {
            $style = ['logo' => Configure::read('MISP.baseurl') . '/organisations/getOrgLogo/' . (int)$org['id']];
        } else {
            $mono = EventCardTool::monogram($org);
            $style = ['mono' => $mono['letters'], 'tint' => $mono['index']];
        }
        return [
            'value' => (string)$org['id'],
            'label' => $org['name'],
            'style' => $style,
        ];
    }

    public static function tagRow(array $r)
    {
        return [
            'value' => $r['Tag']['name'],
            'label' => $r['Tag']['name'],
            'style' => ['colour' => $r['Tag']['colour'] ?: null],
        ];
    }

    public static function clusterRow(array $r)
    {
        $row = [
            'value' => $r['GalaxyCluster']['tag_name'],
            'label' => $r['GalaxyCluster']['value'],
            'style' => [
                'galaxy' => $r['Galaxy']['name'] ?? null,
                'icon' => self::iconClass($r['Galaxy']['icon'] ?? null),
            ],
        ];
        if (isset($r['Galaxy']['type'])) {
            $row['galaxy_type'] = $r['Galaxy']['type'];
            $row['tag_name'] = $r['GalaxyCluster']['tag_name'];
            $row['description'] = self::shorten($r['GalaxyCluster']['description'] ?? null);
            if (isset($r['GalaxyCluster']['default']) && !$r['GalaxyCluster']['default']) {
                $row['custom'] = true;
            }
        }
        return $row;
    }

    /**
     * @param string|null $icon a galaxy's Font Awesome icon name
     * @return string|null
     */
    private static function iconClass($icon)
    {
        if (!$icon || !preg_match('/^[a-z0-9-]+$/', $icon)) {
            return null;
        }
        App::uses('FontAwesomeHelper', 'View/Helper');
        return FontAwesomeHelper::findNamespace($icon) . ' fa-' . $icon;
    }

    /**
     * @param string|null $text
     * @return string|null
     */
    private static function shorten($text)
    {
        if ($text === null || $text === '') {
            return null;
        }
        $text = trim(preg_replace('/\s+/u', ' ', strip_tags($text)));
        if (mb_strlen($text) <= self::DESCRIPTION_LENGTH) {
            return $text;
        }
        return rtrim(mb_substr($text, 0, self::DESCRIPTION_LENGTH - 1)) . '…';
    }

    /**
     * @param array $user
     * @return array the reader's analyst profile plan
     */
    private static function plan(array $user)
    {
        App::uses('ValueLabelPriority', 'Tools/ValueIntelligence');
        return ValueLabelPriority::planFor(ClassRegistry::init('AnalystProfile')->resolveFor($user));
    }

    /**
     * @return int|null position in the profile's list (1 = first), null when absent
     */
    private static function rank(array $plan, $scope, $tier, $key)
    {
        $i = array_search($key, $plan[$scope][$tier] ?? [], true);
        return $i === false ? null : $i + 1;
    }

    /**
     * @param array $user
     * @return string the part of a cache key the reader's ACL depends on
     */
    private static function cacheScope(array $user)
    {
        return empty($user['Role']['perm_site_admin']) ? 'u' . (int)$user['id'] : 'admin';
    }

    private static function cacheGet($key)
    {
        try {
            $cached = RedisTool::init()->get($key);
            if (is_string($cached)) {
                return JsonTool::decode($cached);
            }
        } catch (Exception $e) {
        }
        return null;
    }

    private static function cacheSet($key, array $value)
    {
        try {
            RedisTool::init()->setex($key, self::SCOPES_TTL, JsonTool::encode($value));
        } catch (Exception $e) {
        }
    }
}
