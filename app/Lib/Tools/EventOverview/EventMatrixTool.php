<?php
App::uses('GalaxyMatrixLayout', 'Tools');

/**
 * The overview's compact galaxy matrix: for each matrix galaxy an event
 * uses, its tactics in kill-chain order holding only the techniques found
 * on the event or on its indicators, every tab merged.
 *
 * Pure: the caller fetches the clusters (ACL'd) and the roll-up.
 */
class EventMatrixTool
{
    const ATTACK_TYPE = 'mitre-attack-pattern';

    /**
     * @param array $galaxy Galaxy row, kill_chain_order decoded
     * @return bool
     */
    public static function isMatrixGalaxy(array $galaxy)
    {
        $killChain = $galaxy['kill_chain_order'] ?? null;
        if (is_string($killChain)) {
            $killChain = json_decode($killChain, true);
        }
        if (!is_array($killChain)) {
            return false;
        }
        foreach ($killChain as $columns) {
            if (is_array($columns) && !empty($columns)) {
                return true;
            }
        }
        return false;
    }

    /**
     * A galaxy's tactics in one order across its tabs; ATT&CK's Enterprise
     * order leads so the other domains slot in around it.
     *
     * @param array $galaxy
     * @return array
     */
    public static function tacticOrder(array $galaxy)
    {
        $killChain = $galaxy['kill_chain_order'] ?? [];
        if (is_string($killChain)) {
            $killChain = json_decode($killChain, true);
        }
        $killChain = array_filter((array)$killChain, 'is_array');
        $sequences = [];
        if (($galaxy['type'] ?? '') === self::ATTACK_TYPE) {
            $sequences[] = GalaxyMatrixLayout::mergeColumnOrders(array_map(function ($tab) use ($killChain) {
                return $killChain[$tab];
            }, GalaxyMatrixLayout::enterpriseTabs($killChain)));
        }
        foreach ($killChain as $columns) {
            $sequences[] = $columns;
        }
        return GalaxyMatrixLayout::mergeColumnOrders($sequences);
    }

    /**
     * @param array $hits each: cluster (GalaxyCluster row carrying Galaxy and
     *        meta.kill_chain / meta.external_id), event (ids of the events
     *        carrying it at event level), indicators (event id => indicators)
     * @param int $selfId the viewed event
     * @param array $parentNames galaxy id => [parent T-id => name], for
     *        sub-techniques whose parent is not among the hits
     * @return array galaxies, ATT&CK first, then by technique count
     */
    public static function compact(array $hits, $selfId, array $parentNames = [])
    {
        $galaxies = [];
        foreach (self::collect($hits, $selfId) as $galaxyId => $entry) {
            $galaxies[] = self::galaxyView($entry['galaxy'], $entry['cells'], $parentNames[$galaxyId] ?? []);
        }
        usort($galaxies, function ($a, $b) {
            $attack = ($b['type'] === self::ATTACK_TYPE) <=> ($a['type'] === self::ATTACK_TYPE);
            if ($attack !== 0) {
                return $attack;
            }
            if ($a['techniques'] !== $b['techniques']) {
                return $b['techniques'] <=> $a['techniques'];
            }
            return strcasecmp($a['name'], $b['name']);
        });
        return $galaxies;
    }

    /**
     * A matrix skeleton (Galaxy::getMatrix()) cut down to what a cell
     * needs, small enough to cache.
     *
     * @param array $matrixData
     * @return array killChain, tabs => column => cells
     */
    public static function slimSkeleton(array $matrixData)
    {
        $tabs = [];
        foreach ((array)($matrixData['tabs'] ?? []) as $tab => $columns) {
            foreach ((array)$columns as $column => $cells) {
                foreach ((array)$cells as $cell) {
                    if (!empty($cell['deleted'])) {
                        continue;
                    }
                    $tabs[$tab][$column][] = [
                        'id' => (int)($cell['id'] ?? 0),
                        'uuid' => (string)($cell['uuid'] ?? ''),
                        'value' => (string)($cell['value'] ?? ''),
                        'tag_name' => (string)($cell['tag_name'] ?? ''),
                        'external_id' => (string)($cell['external_id'] ?? ''),
                        'default' => !empty($cell['default']),
                    ];
                }
            }
        }
        return ['killChain' => (array)($matrixData['killChain'] ?? []), 'tabs' => $tabs];
    }

    /**
     * How a tab is named in the modal's tab strip.
     *
     * @param string $tab
     * @param string $galaxyType
     * @return string
     */
    public static function tabLabel($tab, $galaxyType)
    {
        $tab = (string)$tab;
        if ($galaxyType === self::ATTACK_TYPE) {
            if ($tab === 'attack-enterprise') {
                return 'Enterprise';
            }
            if ($tab === 'pre-attack') {
                return 'PRE-ATT&CK';
            }
            if (preg_match('/^(mobile|ics)-attack(?:-(.+))?$/', $tab, $m)) {
                $domain = $m[1] === 'ics' ? 'ICS' : 'Mobile';
                return empty($m[2]) ? $domain : $domain . ' · ' . str_replace('-', ' ', $m[2]);
            }
            if (strpos($tab, 'attack-') === 0) {
                return str_replace('-', ' ', substr($tab, 7));
            }
        }
        return ucwords(str_replace(['-', '_'], ' ', $tab));
    }

    /**
     * One galaxy's full matrix for the modal: its tabs with how many of the
     * event's techniques each holds, and one tab's columns with every
     * technique, those the event uses carrying their state.
     *
     * @param array $skeleton slimSkeleton() of the galaxy, cells the user may see
     * @param array $galaxy Galaxy row
     * @param array $hits as compact() takes them
     * @param int $selfId
     * @param string|null $tab the tab to draw; the busiest one when null or unknown
     * @return array
     */
    public static function full(array $skeleton, array $galaxy, array $hits, $selfId, $tab = null)
    {
        $byTag = [];
        foreach (self::collect($hits, $selfId)[(int)$galaxy['id']]['cells'] ?? [] as $cell) {
            $byTag[$cell['cluster']['tag_name']] = $cell;
        }
        return self::fullOf($skeleton, $galaxy, $byTag, $tab);
    }

    /**
     * One galaxy's full matrix with the techniques carried by the events the
     * user can see in the strong state, for the galaxy page.
     *
     * @param array $skeleton slimSkeleton() of the galaxy, cells the user may see
     * @param array $galaxy Galaxy row
     * @param array $eventCounts cluster tag name => events carrying it
     * @param string|null $tab as full() takes it
     * @return array
     */
    public static function usage(array $skeleton, array $galaxy, array $eventCounts, $tab = null)
    {
        $byTag = [];
        foreach ($eventCounts as $tagName => $count) {
            $byTag[$tagName] = [
                'state' => 'event',
                'onEvent' => true,
                'events' => (int)$count,
                'indicators' => 0,
                'loose' => 0,
                'foreign' => false,
                'origins' => [],
            ];
        }
        return self::fullOf($skeleton, $galaxy, $byTag, $tab);
    }

    /**
     * @param array $byTag cluster tag name => finished cell, for the used techniques
     */
    private static function fullOf(array $skeleton, array $galaxy, array $byTag, $tab)
    {
        $galaxyId = (int)$galaxy['id'];
        $tabKeys = array_map('strval', array_keys($skeleton['killChain']));
        foreach (array_keys($skeleton['tabs']) as $key) {
            if (!in_array((string)$key, $tabKeys, true)) {
                $tabKeys[] = (string)$key;
            }
        }
        $tabs = [];
        foreach ($tabKeys as $key) {
            $active = [];
            foreach ($skeleton['tabs'][$key] ?? [] as $cells) {
                foreach ($cells as $cell) {
                    if (isset($byTag[$cell['tag_name']])) {
                        $active[$cell['tag_name']] = true;
                    }
                }
            }
            $tabs[] = ['key' => $key, 'label' => self::tabLabel($key, $galaxy['type'] ?? ''), 'active' => count($active)];
        }
        $known = array_column($tabs, 'key');
        if ($tab === null || !in_array((string)$tab, $known, true)) {
            $tab = null;
            $best = -1;
            foreach ($tabs as $entry) {
                if ($entry['active'] > $best) {
                    $best = $entry['active'];
                    $tab = $entry['key'];
                }
            }
        }
        $tab = (string)$tab;

        $columns = array_filter($skeleton['tabs'][$tab] ?? []);
        $order = self::orderColumns(self::tacticOrder($galaxy), array_keys($columns));
        $parentNames = GalaxyMatrixLayout::parentNames($columns);
        $grid = [];
        foreach ($order as $column) {
            $groups = [];
            $activeCount = 0;
            foreach (GalaxyMatrixLayout::groupColumn($columns[$column] ?? []) as $group) {
                $own = $group['cell'] === null ? null : self::fullCellView($group['cell'], $group['label'], $byTag);
                $subs = [];
                foreach ($group['subs'] as $sub) {
                    $subs[] = self::fullCellView($sub['cell'], $sub['label'], $byTag);
                }
                usort($subs, function ($a, $b) {
                    return strcasecmp($a['label'], $b['label']);
                });
                $states = array_column(array_merge($own === null ? [] : [$own], $subs), 'state');
                $state = in_array('event', $states, true) ? 'event' : (in_array('indicators', $states, true) ? 'indicators' : 'idle');
                $activeCount += $state === 'idle' ? 0 : 1;
                $groups[] = [
                    'tid' => preg_match('/^T\d+$/', (string)$group['key']) ? (string)$group['key'] : ($own['tid'] ?? ''),
                    'label' => GalaxyMatrixLayout::groupLabel($group, $parentNames),
                    'state' => $state,
                    'own' => $own,
                    'subs' => $subs,
                ];
            }
            usort($groups, function ($a, $b) {
                return strcasecmp($a['label'], $b['label']);
            });
            $grid[] = [
                'key' => $column,
                'label' => GalaxyMatrixLayout::formatTactic($column),
                'active' => $activeCount,
                'groups' => $groups,
            ];
        }

        return [
            'galaxy' => [
                'id' => $galaxyId,
                'uuid' => (string)($galaxy['uuid'] ?? ''),
                'name' => (string)($galaxy['name'] ?? ''),
                'type' => (string)($galaxy['type'] ?? ''),
                'icon' => (string)($galaxy['icon'] ?? ''),
            ],
            'tab' => $tab,
            'tabs' => $tabs,
            'columns' => $grid,
        ];
    }

    /**
     * The present columns in the galaxy's order; one no tab places goes last.
     */
    private static function orderColumns(array $order, array $present)
    {
        $present = array_map('strval', $present);
        $known = array_values(array_intersect($order, $present));
        return array_merge($known, array_values(array_diff($present, $known)));
    }

    private static function fullCellView(array $cell, $label, array $byTag)
    {
        $hit = $byTag[$cell['tag_name']] ?? null;
        return [
            'tid' => (string)$cell['external_id'],
            'label' => (string)$label,
            'state' => $hit === null ? 'idle' : $hit['state'],
            'onEvent' => $hit !== null && $hit['onEvent'],
            'events' => $hit === null ? 0 : ($hit['events'] ?? 0),
            'indicators' => $hit === null ? 0 : $hit['indicators'],
            'loose' => $hit === null ? 0 : $hit['loose'],
            'foreign' => $hit !== null && $hit['foreign'],
            'origins' => $hit === null ? [] : $hit['origins'],
            'cluster' => [
                'id' => (int)$cell['id'],
                'uuid' => (string)$cell['uuid'],
                'value' => (string)$cell['value'],
                'tag_name' => (string)$cell['tag_name'],
            ],
        ];
    }

    /**
     * The hits on matrix galaxies, per galaxy, merged per cluster.
     *
     * @return array galaxy id => [galaxy, cells => key => finished cell]
     */
    private static function collect(array $hits, $selfId)
    {
        $selfId = (int)$selfId;
        $byGalaxy = [];
        foreach ($hits as $hit) {
            $cluster = $hit['cluster'] ?? null;
            $galaxy = $cluster['Galaxy'] ?? null;
            if (empty($cluster) || empty($galaxy) || !self::isMatrixGalaxy($galaxy)) {
                continue;
            }
            $columns = self::columnsOf($cluster);
            if (empty($columns)) {
                continue;
            }
            $galaxyId = (int)$galaxy['id'];
            $key = (string)($cluster['uuid'] ?? $cluster['tag_name'] ?? $cluster['id']);
            if (!isset($byGalaxy[$galaxyId])) {
                $byGalaxy[$galaxyId] = ['galaxy' => $galaxy, 'cells' => []];
            }
            $cell = $byGalaxy[$galaxyId]['cells'][$key] ?? self::cell($cluster, $columns);
            foreach ((array)($hit['event'] ?? []) as $eventId) {
                $cell['eventOrigins'][(int)$eventId] = true;
            }
            foreach ((array)($hit['indicators'] ?? []) as $eventId => $count) {
                if ((int)$count > 0) {
                    $cell['indicatorOrigins'][(int)$eventId] = ($cell['indicatorOrigins'][(int)$eventId] ?? 0) + (int)$count;
                }
            }
            foreach ((array)($hit['loose'] ?? []) as $count) {
                $cell['loose'] += (int)$count;
            }
            $byGalaxy[$galaxyId]['cells'][$key] = $cell;
        }

        $collected = [];
        foreach ($byGalaxy as $galaxyId => $entry) {
            $cells = array_map(function ($cell) use ($selfId) {
                return self::finishCell($cell, $selfId);
            }, array_filter($entry['cells'], function ($cell) {
                return !empty($cell['eventOrigins']) || !empty($cell['indicatorOrigins']);
            }));
            if (!empty($cells)) {
                $collected[$galaxyId] = ['galaxy' => $entry['galaxy'], 'cells' => $cells];
            }
        }
        return $collected;
    }

    /**
     * Parent technique ids the hits' sub-techniques need a name for.
     *
     * @param array $hits as compact() takes them
     * @return array galaxy id => list of parent T-ids
     */
    public static function missingParents(array $hits)
    {
        $present = [];
        $wanted = [];
        foreach ($hits as $hit) {
            $cluster = $hit['cluster'] ?? [];
            $galaxyId = (int)($cluster['Galaxy']['id'] ?? 0);
            $externalId = self::externalId($cluster);
            if (preg_match('/^(T\d+)\.\d+$/', $externalId, $m)) {
                $wanted[$galaxyId][$m[1]] = true;
            } elseif ($externalId !== '') {
                $present[$galaxyId][$externalId] = true;
            }
        }
        $missing = [];
        foreach ($wanted as $galaxyId => $ids) {
            $ids = array_keys(array_diff_key($ids, $present[$galaxyId] ?? []));
            if (!empty($ids)) {
                $missing[$galaxyId] = array_map('strval', $ids);
            }
        }
        return $missing;
    }

    private static function columnsOf(array $cluster)
    {
        $columns = [];
        foreach ((array)($cluster['meta']['kill_chain'] ?? []) as $entry) {
            $parts = explode(':', (string)$entry, 2);
            if (count($parts) === 2 && $parts[1] !== '') {
                $columns[$parts[1]] = true;
            }
        }
        return array_map('strval', array_keys($columns));
    }

    private static function externalId(array $cluster)
    {
        $externalId = $cluster['meta']['external_id'] ?? '';
        if (is_array($externalId)) {
            $externalId = reset($externalId);
        }
        return (string)$externalId;
    }

    private static function cell(array $cluster, array $columns)
    {
        return [
            'value' => (string)($cluster['value'] ?? ''),
            'external_id' => self::externalId($cluster),
            'columns' => $columns,
            'cluster' => [
                'id' => (int)($cluster['id'] ?? 0),
                'uuid' => (string)($cluster['uuid'] ?? ''),
                'value' => (string)($cluster['value'] ?? ''),
                'tag_name' => (string)($cluster['tag_name'] ?? ''),
                'tag_id' => (int)($cluster['tag_id'] ?? 0),
            ],
            'eventOrigins' => [],
            'indicatorOrigins' => [],
            'loose' => 0,
        ];
    }

    private static function finishCell(array $cell, $selfId)
    {
        $events = array_map('intval', array_keys($cell['eventOrigins']));
        $origins = array_values(array_unique(array_merge($events, array_map('intval', array_keys($cell['indicatorOrigins'])))));
        sort($origins);
        $cell['onEvent'] = !empty($events);
        $cell['indicators'] = (int)array_sum($cell['indicatorOrigins']);
        $cell['state'] = $cell['onEvent'] ? 'event' : 'indicators';
        $cell['origins'] = $origins;
        $cell['foreign'] = !in_array((int)$selfId, $origins, true);
        unset($cell['eventOrigins'], $cell['indicatorOrigins']);
        return $cell;
    }

    private static function galaxyView(array $galaxy, array $cells, array $extraParentNames)
    {
        $order = self::tacticOrder($galaxy);
        $byColumn = [];
        foreach ($cells as $cell) {
            foreach ($cell['columns'] as $column) {
                $byColumn[$column][] = $cell;
            }
        }
        $order = self::orderColumns($order, array_keys($byColumn));
        $parentNames = GalaxyMatrixLayout::parentNames($byColumn) + $extraParentNames;

        $tactics = [];
        foreach ($order as $column) {
            if (empty($byColumn[$column])) {
                continue;
            }
            $groups = [];
            foreach (GalaxyMatrixLayout::groupColumn($byColumn[$column]) as $key => $group) {
                $groups[] = self::groupView($group, $parentNames);
            }
            usort($groups, [self::class, 'byWeight']);
            $tactics[] = [
                'key' => $column,
                'label' => GalaxyMatrixLayout::formatTactic($column),
                'groups' => $groups,
            ];
        }

        $onEvent = 0;
        foreach ($cells as $cell) {
            $onEvent += $cell['onEvent'] ? 1 : 0;
        }
        return [
            'id' => (int)$galaxy['id'],
            'uuid' => (string)($galaxy['uuid'] ?? ''),
            'name' => (string)($galaxy['name'] ?? ''),
            'type' => (string)($galaxy['type'] ?? ''),
            'namespace' => (string)($galaxy['namespace'] ?? ''),
            'icon' => (string)($galaxy['icon'] ?? ''),
            'techniques' => count($cells),
            'onEvent' => $onEvent,
            'tactics' => $tactics,
        ];
    }

    private static function groupView(array $group, array $parentNames)
    {
        $own = $group['cell'] === null ? null : self::cellView($group['cell'], $group['label']);
        $subs = [];
        foreach ($group['subs'] as $sub) {
            $subs[] = self::cellView($sub['cell'], $sub['label']);
        }
        usort($subs, [self::class, 'byWeight']);
        $members = array_merge($own === null ? [] : [$own], $subs);
        $onEvent = false;
        $indicators = 0;
        $loose = 0;
        $foreign = true;
        $origins = [];
        foreach ($members as $member) {
            $onEvent = $onEvent || $member['onEvent'];
            $indicators += $member['indicators'];
            $loose += $member['loose'];
            $foreign = $foreign && $member['foreign'];
            $origins = array_merge($origins, $member['origins']);
        }
        $origins = array_values(array_unique($origins));
        sort($origins);
        return [
            'tid' => preg_match('/^T\d+$/', (string)$group['key']) ? (string)$group['key'] : ($own['tid'] ?? ''),
            'label' => GalaxyMatrixLayout::groupLabel($group, $parentNames),
            'state' => $onEvent ? 'event' : 'indicators',
            'onEvent' => $onEvent,
            'indicators' => $indicators,
            'loose' => $loose,
            'foreign' => $foreign,
            'origins' => $origins,
            'own' => $own,
            'subs' => $subs,
        ];
    }

    private static function cellView(array $cell, $label)
    {
        return [
            'tid' => $cell['external_id'],
            'label' => (string)$label,
            'state' => $cell['state'],
            'onEvent' => $cell['onEvent'],
            'indicators' => $cell['indicators'],
            'loose' => $cell['loose'],
            'foreign' => $cell['foreign'],
            'origins' => $cell['origins'],
            'cluster' => $cell['cluster'],
        ];
    }

    private static function byWeight(array $a, array $b)
    {
        if ($a['onEvent'] !== $b['onEvent']) {
            return $b['onEvent'] <=> $a['onEvent'];
        }
        if ($a['indicators'] !== $b['indicators']) {
            return $b['indicators'] <=> $a['indicators'];
        }
        return strcasecmp($a['label'], $b['label']);
    }
}
