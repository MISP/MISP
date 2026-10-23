<?php
App::uses('EventContextTool', 'Tools/EventOverview');
App::uses('DistributionLevel', 'Tools');
App::uses('ValueLabelPriority', 'Tools/ValueIntelligence');

/**
 * Shapes one event of the index into what its card draws: three one-line
 * context rows, the marking slots, the publish state and the distribution.
 *
 * Pure: the controller fetches everything for the page and passes it in.
 */
class EventCardTool
{
    const MONOGRAM_STOP = ['of', 'the', 'and', 'for', 'de', 'du', 'di', 'van', 'von', 'la', 'le'];

    /**
     * @param array $context EventContextTool::rows() output
     * @param array|null $profile The reader's analyst profile, which ranks
     *                            the classification row's tags and clusters
     *                            together
     * @return array attribution / behaviour / classification chip lists, and
     *               the attribution and technique counts
     */
    public static function rows(array $context, $profile = null)
    {
        $rows = ['attribution' => [], 'behaviour' => [], 'classification' => []];
        // Pinned taxonomies have their own slot in the markings.
        $pinned = array_flip(self::pinned($profile));
        $seen = [];
        $once = function ($key) use (&$seen) {
            if (isset($seen[$key])) {
                return false;
            }
            $seen[$key] = true;
            return true;
        };
        $techniques = 0;
        $galaxies = self::galaxiesByType($context);

        foreach ($context['attribution'] ?? [] as $item) {
            if (!$once('a|' . $item['name'])) {
                continue;
            }
            if ($item['kind'] === 'unheld') {
                $galaxyTag = ['type' => $item['key'], 'value' => $item['name']];
                $rows['attribution'][] = [
                    'kind' => 'unheld',
                    'label' => $item['name'],
                    'galaxy' => $item['galaxy']['name'] ?? $item['key'],
                    'attribution' => true,
                    'source' => ['unheld' => self::unheldCluster($galaxyTag, $galaxies)],
                    'priority' => $item['priority'] ?? null,
                ];
            } else {
                $rows['attribution'][] = self::clusterChip($item, true);
            }
        }

        foreach ($context['behaviour'] ?? [] as $item) {
            $id = $item['technique'] ?? $item['name'];
            if (!$once('t|' . $id)) {
                continue;
            }
            $techniques++;
            $rows['behaviour'][] = [
                'kind' => 'technique',
                'label' => $id,
                'name' => EventContextTool::techniqueName($item['cluster'] ?? []),
                'unheld' => false,
                'source' => ['cluster' => $item['cluster'] ?? []],
            ];
        }

        foreach ($context['classification'] ?? [] as $item) {
            if ($item['kind'] !== 'tag') {
                continue;
            }
            $galaxyTag = self::galaxyTag($item['name']);
            if ($galaxyTag === null) {
                continue;
            }
            if (self::routesToBehaviour($galaxyTag)) {
                $technique = self::technique($galaxyTag['value']);
                if ($once('t|' . $technique['id'])) {
                    $techniques++;
                    $rows['behaviour'][] = [
                        'kind' => 'technique',
                        'label' => $technique['id'],
                        'name' => $technique['name'],
                        'unheld' => true,
                        'source' => ['unheld' => self::unheldCluster($galaxyTag, $galaxies)],
                    ];
                }
            }
        }

        foreach ($context['mitigation'] ?? [] as $item) {
            $id = $item['technique'] ?? $item['name'];
            if ($once('m|' . $id)) {
                $rows['behaviour'][] = [
                    'kind' => 'mitigation',
                    'label' => $id,
                    'name' => EventContextTool::techniqueName($item['cluster'] ?? []),
                    'source' => ['cluster' => $item['cluster'] ?? []],
                ];
            }
        }

        foreach ($context['clusters'] ?? [] as $item) {
            $type = $item['cluster']['Galaxy']['type'] ?? $item['key'];
            if ($once('c|' . $type . '|' . $item['name'])) {
                $rows['classification'][] = self::clusterChip($item, false) + [
                    'key' => $type,
                    'scope' => ValueLabelPriority::GALAXIES,
                ];
            }
        }

        $folded = 0;
        foreach ($context['classification'] ?? [] as $item) {
            if ($item['kind'] !== 'tag') {
                continue;
            }
            $galaxyTag = self::galaxyTag($item['name']);
            if ($galaxyTag !== null) {
                if (self::routesToBehaviour($galaxyTag)) {
                    continue;
                }
                if (self::isUuid($galaxyTag['value'])) {
                    $folded++;
                } elseif ($once('u|' . $galaxyTag['value'])) {
                    $rows['classification'][] = [
                        'kind' => 'unheld',
                        'label' => $galaxyTag['value'],
                        'galaxy' => $galaxyTag['type'],
                        'source' => ['unheld' => self::unheldCluster($galaxyTag, $galaxies)],
                        'key' => $galaxyTag['type'],
                        'scope' => ValueLabelPriority::GALAXIES,
                    ];
                }
                continue;
            }
            if ($item['key'] !== null && isset($pinned[$item['key']])) {
                continue;
            }
            $tag = $item['tag']['Tag'] ?? [];
            $parts = self::tagParts($item['name']);
            $rows['classification'][] = [
                'kind' => 'tag',
                'label' => $parts['value'],
                'namespace' => $parts['namespace'],
                'name' => $item['name'],
                'colour' => $tag['colour'] ?? null,
                'source' => ['tag' => $item['tag']],
                'key' => $item['key'],
                'scope' => ValueLabelPriority::TAXONOMIES,
            ];
        }
        $rows['classification'] = ValueLabelPriority::across($rows['classification'], $profile);
        if ($folded) {
            $rows['classification'][] = ['kind' => 'fold', 'count' => $folded];
        }

        $rows['attribution_count'] = count($rows['attribution']);
        $rows['technique_count'] = $techniques;
        return $rows;
    }

    /**
     * One slot per marking namespace of the profile, present or absent, then
     * the profile's other pinned taxonomies when the event carries them.
     *
     * @param array $context EventContextTool::rows() output
     * @param array $namespaces ValueLabelPriority::markings($profile)
     * @param array $pinned the plan's pinned taxonomies, in order
     * @param array $descriptions tag name => tagDescription()
     * @return array slots
     */
    public static function markings(array $context, array $namespaces, array $pinned = [], array $descriptions = [])
    {
        $present = [];
        foreach ($context['markings'] ?? [] as $item) {
            if (!isset($present[$item['key']])) {
                $present[$item['key']] = $item;
            }
        }
        $absent = [];
        foreach ($context['markings_absent'] ?? [] as $missing) {
            $absent[$missing['key']] = true;
        }

        $pinnedTags = [];
        foreach ($context['classification'] ?? [] as $item) {
            if ($item['kind'] === 'tag' && $item['key'] !== null && in_array($item['key'], $pinned, true)) {
                $pinnedTags[$item['key']][] = $item;
            }
        }

        $slots = [];
        $order = array_merge(array_values(array_diff($namespaces, $pinned)), $pinned);
        foreach ($order as $namespace) {
            if (!in_array($namespace, $namespaces, true)) {
                if (empty($pinnedTags[$namespace])) {
                    continue;
                }
                $slots[] = $namespace === 'admiralty-scale'
                    ? self::admiralty($pinnedTags[$namespace], $descriptions)
                    : self::pinnedSlot($namespace, $pinnedTags[$namespace], $descriptions);
                continue;
            }
            if (isset($present[$namespace])) {
                $item = $present[$namespace];
                $colour = $item['tag']['Tag']['colour'] ?? null;
                $value = substr($item['name'], strpos($item['name'], ':') + 1);
                $slots[] = [
                    'key' => $namespace,
                    'present' => true,
                    'name' => $item['name'],
                    'value' => trim($value, '"'),
                    'colour' => $colour,
                    'neutral' => self::isNeutral($colour),
                ];
            } elseif (isset($absent[$namespace])) {
                $slots[] = ['key' => $namespace, 'present' => false];
            }
        }
        return ['slots' => $slots];
    }

    /**
     * @param array|null $profile
     * @return array the plan's pinned taxonomy namespaces, in order
     */
    public static function pinned($profile)
    {
        return ValueLabelPriority::planFor($profile)[ValueLabelPriority::TAXONOMIES][ValueLabelPriority::PINNED] ?? [];
    }

    /**
     * The reader's grade of an organisation.
     *
     * @param array $org uuid
     * @param array $grades ValueTrustTool::planFor($profile)['grades']
     * @return string|null A…G, null when ungraded
     */
    public static function grade(array $org, array $grades)
    {
        $uuid = strtolower(trim((string)($org['uuid'] ?? '')));
        $grade = $uuid === '' ? null : ($grades[$uuid] ?? null);
        return is_string($grade) && preg_match('/^[A-G]$/', $grade) ? $grade : null;
    }

    /**
     * @param array|false|null $taxonomy Taxonomy::getTaxonomyForTag() for one tag
     * @return array predicate, entry: their expanded names, null when unknown
     */
    public static function tagDescription($taxonomy)
    {
        $predicate = $taxonomy['TaxonomyPredicate'][0] ?? [];
        $entry = $predicate['TaxonomyEntry'][0] ?? [];
        return [
            'predicate' => ($predicate['expanded'] ?? '') !== '' ? $predicate['expanded'] : null,
            'entry' => ($entry['expanded'] ?? '') !== '' ? $entry['expanded'] : null,
        ];
    }

    /**
     * pending: published once and changed since — the event page's rule.
     *
     * @param array $event Event row
     * @return string pending | published | unpublished
     */
    public static function state(array $event)
    {
        $published = (int)($event['publish_timestamp'] ?? 0);
        if ($published > 0 && (int)($event['timestamp'] ?? 0) > $published) {
            return 'pending';
        }
        return empty($event['published']) ? 'unpublished' : 'published';
    }

    /**
     * @param mixed $level
     * @param array|null $sharingGroup id, name
     * @return array level, icon, label, style (the badge's theme colours),
     *  sharing_group (id, name) when the level is a named sharing group
     */
    public static function distribution($level, $sharingGroup = null)
    {
        $meta = DistributionLevel::get($level);
        $label = $meta['label'];
        $group = null;
        if ((int)$level === 4 && !empty($sharingGroup['name'])) {
            $label = __('Sharing group %s', $sharingGroup['name']);
            $group = ['id' => (int)($sharingGroup['id'] ?? 0), 'name' => (string)$sharingGroup['name']];
        }
        return [
            'level' => $level,
            'icon' => $meta['icon'],
            'label' => $label,
            'style' => sprintf(
                '--dk-dbg:%s;--dk-dfg:%s;--dk-dbd:%s',
                DistributionLevel::themed($meta, 'bg'),
                DistributionLevel::themed($meta, 'fg'),
                DistributionLevel::themed($meta, 'border', '33')
            ),
            'sharing_group' => $group,
        ];
    }

    /**
     * Two letters and one of six tints, stable per organisation.
     *
     * @param array $org name, uuid
     * @return array letters, index
     */
    public static function monogram(array $org)
    {
        $name = (string)($org['name'] ?? '');
        if ($name === '') {
            $name = '?';
        }
        $words = array_values(array_filter(
            preg_split('/[\s\-_.]+/u', $name),
            function ($word) {
                return $word !== '' && !in_array(strtolower($word), self::MONOGRAM_STOP, true);
            }
        ));
        if (count($words) >= 2) {
            $letters = self::chars($words[0], 1) . self::chars($words[1], 1);
        } else {
            $letters = self::chars($words[0] ?? $name, 2);
        }
        $seed = (string)($org['uuid'] ?? '') ?: $name;
        $hash = 0;
        for ($i = 0, $n = strlen($seed); $i < $n; $i++) {
            $hash = ($hash * 31 + ord($seed[$i])) & 0xFFFFFFFF;
        }
        return ['letters' => strtoupper($letters), 'index' => $hash % 6];
    }

    /**
     * @param int $n
     * @return string 999, 1.2k, 370k, 1.4M
     */
    public static function compactCount($n)
    {
        $n = (int)$n;
        if ($n >= 1000000) {
            return self::trimZero(round($n / 1000000, 1)) . 'M';
        }
        if ($n >= 10000) {
            return round($n / 1000) . 'k';
        }
        if ($n >= 1000) {
            return self::trimZero(round($n / 1000, 1)) . 'k';
        }
        return (string)$n;
    }

    /**
     * @param int $timestamp
     * @param int $now
     * @return string
     */
    public static function ago($timestamp, $now)
    {
        $s = max(0, (int)$now - (int)$timestamp);
        $m = $s / 60;
        $h = $m / 60;
        $d = $h / 24;
        if ($m < 1) {
            return __('just now');
        }
        if ($h < 1) {
            return __('%s min ago', round($m));
        }
        if ($d < 1) {
            return __('%s h ago', round($h));
        }
        if ($d < 14) {
            return __('%s d ago', round($d));
        }
        if ($d < 60) {
            return __('%s wk ago', round($d / 7));
        }
        if ($d < 365) {
            return __('%s mo ago', round($d / 30.4));
        }
        return __('%s y ago', self::trimZero(round($d / 365.25, 1)));
    }

    /**
     * The admiralty-scale tags as one code: source reliability upper-cased,
     * information credibility as its digit, `·` for a missing half.
     */
    private static function admiralty(array $items, array $descriptions)
    {
        $halves = ['source-reliability' => null, 'information-credibility' => null];
        $says = [];
        foreach ($items as $item) {
            if (!preg_match('/^admiralty-scale:([a-z-]+)="?([^"]*)"?$/i', trim($item['name']), $m)) {
                continue;
            }
            $predicate = strtolower($m[1]);
            if (!array_key_exists($predicate, $halves) || $halves[$predicate] !== null) {
                continue;
            }
            $value = $predicate === 'source-reliability' ? strtoupper($m[2]) : $m[2];
            $halves[$predicate] = $value;
            $description = $descriptions[$item['name']] ?? [];
            $says[$predicate] = ($description['predicate'] ?? $predicate) . ' ' . $value
                . (empty($description['entry']) ? '' : ' — ' . $description['entry']);
        }
        if ($halves['source-reliability'] === null && $halves['information-credibility'] === null) {
            return self::pinnedSlot('admiralty-scale', $items, $descriptions);
        }
        return [
            'key' => 'admiralty-scale',
            'present' => true,
            'kind' => 'admiralty',
            'code' => ($halves['source-reliability'] ?? '·') . ($halves['information-credibility'] ?? '·'),
            'title' => implode(' · ', array_filter(array_replace(array_fill_keys(array_keys($halves), null), $says))),
        ];
    }

    private static function pinnedSlot($namespace, array $items, array $descriptions)
    {
        $tags = [];
        foreach ($items as $item) {
            $parts = self::tagParts($item['name']);
            $description = $descriptions[$item['name']] ?? [];
            $tags[] = [
                'name' => $item['name'],
                'value' => $parts['value'],
                'colour' => $item['tag']['Tag']['colour'] ?? null,
                'title' => $item['name'] . (empty($description['entry']) ? '' : ' — ' . $description['entry']),
            ];
        }
        return ['key' => $namespace, 'present' => true, 'kind' => 'pinned', 'tags' => $tags];
    }

    private static function clusterChip(array $item, $attribution)
    {
        $cluster = $item['cluster'] ?? [];
        return [
            'kind' => 'cluster',
            'label' => $item['name'],
            'galaxy' => $cluster['Galaxy']['name'] ?? null,
            'icon' => $cluster['Galaxy']['icon'] ?? null,
            'relationship' => $cluster['relationship_type'] ?? null,
            'attribution' => $attribution,
            'source' => ['cluster' => $cluster],
            'priority' => $item['priority'] ?? null,
        ];
    }

    /**
     * The galaxies the event's resolved clusters belong to, by type, so an
     * unresolved tag of the same type lists alongside them.
     */
    private static function galaxiesByType(array $context)
    {
        $galaxies = [];
        foreach (['attribution', 'behaviour', 'clusters', 'mitigation'] as $row) {
            foreach ($context[$row] ?? [] as $item) {
                $galaxy = $item['cluster']['Galaxy'] ?? null;
                if (!empty($galaxy['type']) && !isset($galaxies[$galaxy['type']])) {
                    $galaxies[$galaxy['type']] = $galaxy;
                }
            }
        }
        return $galaxies;
    }

    /**
     * A flat cluster row, as TagChipHelper::clusters() reads it, for a galaxy
     * tag whose cluster the instance does not hold.
     */
    private static function unheldCluster(array $galaxyTag, array $galaxies)
    {
        $galaxy = $galaxies[$galaxyTag['type']] ?? null;
        return [
            'value' => $galaxyTag['value'],
            'galaxy' => $galaxy['name'] ?? $galaxyTag['type'],
            'galaxy_id' => $galaxy['id'] ?? null,
            'icon' => $galaxy['icon'] ?? null,
        ];
    }

    /**
     * @param string $name
     * @return array|null type, value of a `misp-galaxy:type="value"` tag
     */
    private static function galaxyTag($name)
    {
        if (!preg_match('/^misp-galaxy:([^=]+)="(.*)"$/s', trim($name), $m)) {
            return null;
        }
        return ['type' => $m[1], 'value' => $m[2]];
    }

    private static function routesToBehaviour(array $galaxyTag)
    {
        return strpos($galaxyTag['type'], 'attack-pattern') !== false
            && self::technique($galaxyTag['value']) !== null;
    }

    private static function technique($value)
    {
        if (!preg_match('/^(.*) - (T\d{4}(?:\.\d{3})?)$/s', $value, $m)) {
            return null;
        }
        return ['id' => $m[2], 'name' => $m[1]];
    }

    private static function tagParts($name)
    {
        $name = trim($name);
        if (preg_match('/^([^:="]+):([^=]+)="(.*)"$/s', $name, $m)) {
            return ['namespace' => $m[2], 'value' => $m[3]];
        }
        if (preg_match('/^([^:]+):(.+)$/s', $name, $m)) {
            return ['namespace' => $m[1], 'value' => $m[2]];
        }
        return ['namespace' => null, 'value' => $name];
    }

    private static function isUuid($value)
    {
        return (bool)preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-/i', $value);
    }

    private static function isNeutral($colour)
    {
        return empty($colour) || (bool)preg_match('/^#f{3}(f{3})?$/i', $colour);
    }

    private static function chars($word, $n)
    {
        preg_match('/^.{0,' . (int)$n . '}/su', $word, $m);
        return $m[0];
    }

    private static function trimZero($n)
    {
        return preg_replace('/\.0$/', '', (string)$n);
    }
}
