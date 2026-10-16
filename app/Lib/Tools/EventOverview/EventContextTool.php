<?php
App::uses('ValueLabelPriority', 'Tools/ValueIntelligence');
App::uses('GalaxyCategory', 'Tools');

/**
 * Sorts an event's labels into the rows the overview draws — markings,
 * attribution, behaviour, classification, mitigation — in the order the
 * reader's analyst profile asks for. Labels found only on the event's
 * indicators join their row marked as such, with how many carry them.
 *
 * The caller fetches, applies the ACL and passes everything in; only
 * galaxy categories are read here, through GalaxyCategory.
 */
class EventContextTool
{
    /** Cluster meta keys holding a technique's id, first match wins; ATT&CK for ICS uses its own. */
    const TECHNIQUE_ID_KEYS = ['external_id', 'Technique ID'];

    /**
     * @param array $eventTags EventTag rows, each carrying Tag
     * @param array $eventClusters GalaxyCluster rows on the event, each carrying Galaxy
     * @param array|null $rollup tag id => indicators carrying it; null when not computed
     * @param array $rollupTags tag id => Tag row, for the rolled-up ids
     * @param array $rollupClusters tag id => GalaxyCluster row (with Galaxy) for rolled-up galaxy tags
     * @param array|null $profile The reader's analyst profile
     * @param array $permitted taxonomies/galaxies the instance enables, as pivotLabels() gives it
     * @return array
     */
    public static function rows(
        array $eventTags,
        array $eventClusters,
        $rollup,
        array $rollupTags,
        array $rollupClusters,
        $profile,
        array $permitted = []
    ) {
        $plan = ValueLabelPriority::planFor($profile);
        $markingNamespaces = ValueLabelPriority::markings($profile);
        $attribution = array_flip(
            ValueLabelPriority::attribution($profile) ?: GalaxyCategory::typesIn(GalaxyCategory::NAMED_THREAT)
        );
        $rollup = is_array($rollup) ? $rollup : [];

        $rows = [
            'markings' => [],
            'attribution' => [],
            'behaviour' => [],
            'classification' => [],
            'clusters' => [],
            'mitigation' => [],
        ];

        $seenTagIds = [];
        $unheldAttribution = [];
        $clusterTagIds = [];
        foreach ($eventClusters as $cluster) {
            if (!empty($cluster['tag_id'])) {
                $clusterTagIds[(int)$cluster['tag_id']] = true;
            }
        }

        foreach ($eventTags as $eventTag) {
            $tag = $eventTag['Tag'] ?? null;
            if (empty($tag) || !empty($tag['hide_tag'])) {
                continue;
            }
            $tagId = (int)$tag['id'];
            $seenTagIds[$tagId] = true;
            if (!empty($tag['is_galaxy']) && isset($clusterTagIds[$tagId])) {
                continue;
            }
            $unheld = self::attributionTag($tag['name'], $attribution);
            if ($unheld !== null) {
                $unheldAttribution[] = [
                    'kind' => 'unheld',
                    'tag' => $eventTag,
                    'key' => $unheld['type'],
                    'name' => $unheld['value'],
                    'level' => 'event',
                    'count' => $rollup[$tagId] ?? 0,
                ];
                continue;
            }
            $namespace = ValueLabelPriority::namespaceOf($tag['name']);
            $item = [
                'kind' => 'tag',
                'tag' => $eventTag,
                'key' => $namespace,
                'name' => $tag['name'],
                'level' => 'event',
                'count' => $rollup[$tagId] ?? 0,
            ];
            if ($namespace !== null && in_array($namespace, $markingNamespaces, true)) {
                $rows['markings'][] = $item;
            } else {
                $rows['classification'][] = $item;
            }
        }

        foreach ($eventClusters as $cluster) {
            $tagId = (int)($cluster['tag_id'] ?? 0);
            self::placeCluster($rows, $cluster, 'event', $rollup[$tagId] ?? 0, $attribution);
        }
        $galaxies = [];
        foreach ($eventClusters as $cluster) {
            $type = mb_strtolower((string)($cluster['Galaxy']['type'] ?? ''));
            if ($type !== '' && !isset($galaxies[$type])) {
                $galaxies[$type] = $cluster['Galaxy'];
            }
        }
        foreach ($unheldAttribution as $item) {
            $rows['attribution'][] = $item + ['galaxy' => $galaxies[$item['key']] ?? null];
        }

        foreach ($rollup as $tagId => $count) {
            if (isset($seenTagIds[$tagId]) || empty($rollupTags[$tagId])) {
                continue;
            }
            $tag = $rollupTags[$tagId];
            if (!empty($tag['hide_tag'])) {
                continue;
            }
            if (!empty($tag['is_galaxy'])) {
                if (!empty($rollupClusters[$tagId])) {
                    self::placeCluster($rows, $rollupClusters[$tagId], 'indicators', $count, $attribution);
                }
                continue;
            }
            $namespace = ValueLabelPriority::namespaceOf($tag['name']);
            if ($namespace !== null && in_array($namespace, $markingNamespaces, true)) {
                continue;
            }
            $rows['classification'][] = [
                'kind' => 'tag',
                'tag' => ['Tag' => $tag, 'local' => 0],
                'key' => $namespace,
                'name' => $tag['name'],
                'level' => 'indicators',
                'count' => $count,
            ];
        }

        $rows['markings'] = self::orderMarkings($rows['markings'], $markingNamespaces);
        $rows['classification'] = self::byLevel(
            ValueLabelPriority::labels($rows['classification'], $plan, ValueLabelPriority::TAXONOMIES)
        );
        foreach (['attribution', 'clusters', 'mitigation'] as $row) {
            $rows[$row] = self::byLevel(
                ValueLabelPriority::labels($rows[$row], $plan, ValueLabelPriority::GALAXIES)
            );
        }
        $rows['behaviour'] = self::byLevel($rows['behaviour']);

        $groups = [];
        foreach ($rows['classification'] as $item) {
            if ($item['key'] !== null) {
                $groups[$item['key']] = ['key' => $item['key']];
            }
        }
        $presentMarkings = [];
        foreach ($rows['markings'] as $item) {
            $presentMarkings[$item['key']] = ['key' => $item['key']];
        }
        $rows['markings_absent'] = array_values(array_filter(
            ValueLabelPriority::absent(
                array_values($presentMarkings),
                $plan,
                ValueLabelPriority::TAXONOMIES,
                $permitted['taxonomies'] ?? null
            ),
            function ($missing) use ($markingNamespaces) {
                return in_array($missing['key'], $markingNamespaces, true);
            }
        ));
        foreach ($markingNamespaces as $namespace) {
            $groups[$namespace] = ['key' => $namespace];
        }
        $absent = ValueLabelPriority::absent(
            array_values($groups),
            $plan,
            ValueLabelPriority::TAXONOMIES,
            $permitted['taxonomies'] ?? null
        );
        foreach (array_reverse($absent) as $missing) {
            array_unshift($rows['classification'], [
                'kind' => 'absent',
                'key' => $missing['key'],
                'level' => 'event',
                'count' => 0,
            ]);
        }

        return $rows;
    }

    /**
     * A galaxy tag of an attribution galaxy, for when the instance holds no
     * cluster for it — typically a value the galaxy has since folded into
     * another cluster's synonyms.
     *
     * @return array|null type, value
     */
    private static function attributionTag($name, array $attribution)
    {
        if (!preg_match('/^misp-galaxy:([^=]+)="(.*)"$/s', trim($name), $m)) {
            return null;
        }
        $type = mb_strtolower($m[1]);
        if (!isset($attribution[$type]) || preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-/i', $m[2])) {
            return null;
        }
        return ['type' => $type, 'value' => $m[2]];
    }

    private static function placeCluster(array &$rows, array $cluster, $level, $count, array $attribution)
    {
        $type = mb_strtolower((string)($cluster['Galaxy']['type'] ?? $cluster['type'] ?? ''));
        $item = [
            'kind' => 'cluster',
            'cluster' => $cluster,
            'key' => $type,
            'name' => $cluster['value'] ?? '',
            'level' => $level,
            'count' => $count,
        ];
        $classified = GalaxyCategory::of($type);
        if (isset($attribution[$type])) {
            $rows['attribution'][] = $item;
        } elseif ($classified === null
            ? strpos($type, 'attack-pattern') !== false
            : GalaxyCategory::isAttackPattern($type)
        ) {
            $item['technique'] = self::techniqueId($cluster);
            $rows['behaviour'][] = $item;
        } elseif ($classified === null
            ? strpos($type, 'course-of-action') !== false
            : $classified['category'] === GalaxyCategory::DEFENSIVE
                && $classified['sub_category'] === GalaxyCategory::COURSE_OF_ACTION
        ) {
            $item['technique'] = self::techniqueId($cluster);
            $rows['mitigation'][] = $item;
        } else {
            $rows['clusters'][] = $item;
        }
    }

    /**
     * A row's cluster items split by parent galaxy, largest group first,
     * each group keeping the order its items were given.
     *
     * @param array $items
     * @return array list of ['galaxy' => Galaxy row, 'items' => [...]]
     */
    public static function byGalaxy(array $items)
    {
        $groups = [];
        foreach ($items as $item) {
            $galaxy = $item['cluster']['Galaxy'] ?? [];
            $key = !empty($galaxy['id']) ? 'id:' . $galaxy['id'] : 'type:' . $item['key'];
            if (!isset($groups[$key])) {
                $groups[$key] = [
                    'galaxy' => $galaxy + ['name' => $item['key']],
                    'items' => [],
                ];
            }
            $groups[$key]['items'][] = $item;
        }
        $groups = array_values($groups);
        $order = array_keys($groups);
        usort($order, function ($a, $b) use ($groups) {
            return count($groups[$b]['items']) <=> count($groups[$a]['items']) ?: $a <=> $b;
        });
        return array_map(function ($index) use ($groups) {
            return $groups[$index];
        }, $order);
    }

    /**
     * An ATT&CK cluster's id, from its meta or from the "Name - T1234" value.
     *
     * @param array $cluster
     * @return string|null
     */
    public static function techniqueId(array $cluster)
    {
        foreach (self::TECHNIQUE_ID_KEYS as $key) {
            $external = $cluster['meta'][$key] ?? null;
            if (is_array($external)) {
                $external = reset($external);
            }
            if (is_string($external) && $external !== '') {
                return $external;
            }
        }
        if (preg_match('/ - ([A-Z]{1,3}\d{4}(?:\.\d{3})?)$/', (string)($cluster['value'] ?? ''), $m)) {
            return $m[1];
        }
        return null;
    }

    /**
     * A technique's name without the trailing id its cluster value carries.
     */
    public static function techniqueName(array $cluster)
    {
        return preg_replace('/ - [A-Z]{1,3}\d{4}(?:\.\d{3})?$/', '', (string)($cluster['value'] ?? ''));
    }

    private static function orderMarkings(array $items, array $namespaces)
    {
        $rank = array_flip($namespaces);
        usort($items, function ($a, $b) use ($rank) {
            $ra = $rank[$a['key']] ?? PHP_INT_MAX;
            $rb = $rank[$b['key']] ?? PHP_INT_MAX;
            if ($ra !== $rb) {
                return $ra <=> $rb;
            }
            return self::severity($a) <=> self::severity($b);
        });
        return $items;
    }

    private static function severity(array $item)
    {
        $order = ValueLabelPriority::HANDLING[$item['key']] ?? null;
        if ($order === null) {
            return 0;
        }
        $leaf = mb_strtolower(trim(substr($item['name'], strlen($item['key']) + 1), '"'));
        return $order[$leaf] ?? count($order);
    }

    /**
     * Event-level labels ahead of indicator-only ones, each half keeping
     * the order it was given.
     */
    private static function byLevel(array $items)
    {
        $event = $indicators = [];
        foreach ($items as $item) {
            if ($item['level'] === 'event') {
                $event[] = $item;
            } else {
                $indicators[] = $item;
            }
        }
        return array_merge($event, $indicators);
    }
}
