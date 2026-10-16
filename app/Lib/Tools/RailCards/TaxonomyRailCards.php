<?php
App::uses('LazyRailCards', 'Tools/RailCards');
App::uses('FileAccessTool', 'Tools');

/**
 * Rail cards for a taxonomy. $taxonomy is Taxonomy::getTaxonomy($id), with
 * each entry's existing_tag resolved.
 */
class TaxonomyRailCards extends LazyRailCards
{
    const PREDICATE_LIMIT = 5;
    const USAGE_LIMIT = 10;

    protected function railCardUrl()
    {
        return '/taxonomies/railCard/';
    }

    protected function lazyCards()
    {
        return [
            'taxonomy-usage' => ['list', __('Most used'), 'fas fa-ranking-star', 'usage'],
        ];
    }

    /**
     * The vocabulary: its tags by whether they exist on this instance, by
     * predicate, and the ones carrying a score or an exclusivity rule.
     *
     * @param array $taxonomy
     * @return array
     */
    public function inventory(array $taxonomy)
    {
        $namespace = $taxonomy['Taxonomy']['namespace'];
        $entries = $taxonomy['entries'];
        $total = count($entries);
        $created = $hidden = 0;
        $predicates = [];
        $scores = [];
        $exclusive = 0;
        foreach ($entries as $entry) {
            if (!empty($entry['existing_tag'])) {
                if (!empty($entry['existing_tag']['Tag']['hide_tag'])) {
                    $hidden++;
                } else {
                    $created++;
                }
            }
            $rest = substr($entry['tag'], strlen($namespace) + 1);
            $predicate = explode('=', $rest, 2)[0];
            $predicates[$predicate] = ($predicates[$predicate] ?? 0) + 1;
            if (isset($entry['numerical_value']) && is_numeric($entry['numerical_value'])) {
                $scores[] = $entry['numerical_value'] + 0;
            }
            if (!empty($taxonomy['Taxonomy']['exclusive']) || !empty($entry['exclusive_predicate'])) {
                $exclusive++;
            }
        }
        $groups = [];
        if ($total) {
            $groups[] = [
                'key' => 'tags',
                'label' => __('On this instance'),
                'icon' => 'fas fa-tag',
                'color' => 'tag',
                'count' => $total,
                'partition' => true,
                'facets' => array_values(array_filter([
                    $created ? ['label' => __('Created'), 'count' => $created, 'tone' => 'ok'] : null,
                    $hidden ? ['label' => __('Hidden'), 'count' => $hidden, 'tone' => 'warn'] : null,
                    $total - $created - $hidden
                        ? ['label' => __('Not created'), 'count' => $total - $created - $hidden, 'tone' => 'muted']
                        : null,
                ])),
            ];
        }
        if (count($predicates) > 1 && count($predicates) < $total) {
            arsort($predicates);
            $facets = [];
            foreach (array_slice($predicates, 0, self::PREDICATE_LIMIT, true) as $predicate => $count) {
                $facets[] = ['label' => (string)$predicate, 'count' => $count];
            }
            $groups[] = [
                'key' => 'predicates',
                'label' => __n('%s predicate', '%s predicates', count($predicates), count($predicates)),
                'icon' => 'fas fa-list-ul',
                'count' => $total,
                'partition' => true,
                'facets' => $facets,
                'more' => max(0, count($predicates) - self::PREDICATE_LIMIT),
            ];
        }
        if (!empty($scores)) {
            $min = min($scores);
            $max = max($scores);
            $groups[] = [
                'key' => 'scored',
                'label' => __('With a numerical value'),
                'icon' => 'fas fa-gauge',
                'count' => count($scores),
                'facets' => [['label' => $min == $max ? (string)$min : __('%s to %s', $min, $max)]],
            ];
        }
        if ($exclusive) {
            $groups[] = [
                'key' => 'exclusive',
                'label' => __('Mutually exclusive'),
                'icon' => 'fas fa-code-fork',
                'count' => $exclusive,
            ];
        }
        return RailCard::inventory(
            'taxonomy-inventory',
            __('Vocabulary'),
            'fas fa-book',
            ['count' => $total, 'label' => __n('tag', 'tags', $total)],
            $groups,
            false,
            [
                'link' => ['label' => __('Tags'), 'href' => '#tab-tags'],
                'empty' => __('This taxonomy defines no tag.'),
            ]
        );
    }

    /**
     * The taxonomy's tags carried by the most events the user can see.
     *
     * @param array $user
     * @param array $taxonomy
     * @return array
     */
    public function usage(array $user, array $taxonomy)
    {
        $byTag = [];
        foreach ($taxonomy['entries'] as $entry) {
            if (!empty($entry['existing_tag'])) {
                $byTag[(int)$entry['existing_tag']['Tag']['id']] = $entry;
            }
        }
        $counts = ClassRegistry::init('EventTag')->countForTags(array_keys($byTag), $user);
        $counts = array_filter(array_map('intval', $counts));
        arsort($counts);
        $rows = [];
        foreach (array_slice($counts, 0, self::USAGE_LIMIT, true) as $tagId => $count) {
            $rows[] = [
                'label' => $byTag[$tagId]['expanded'],
                'href' => '/events/index/searchtag:' . $tagId,
                'meta' => [$byTag[$tagId]['tag']],
                'count' => $count,
            ];
        }
        $used = count($counts);
        list(, $title, $icon) = $this->head('taxonomy-usage');
        return RailCard::rows(
            'taxonomy-usage',
            $title,
            $icon,
            $rows,
            $used > count($rows)
                ? ['label' => __('%s tags in use', number_format($used)), 'href' => '#tab-tags']
                : null,
            ['empty' => __('No event carries a tag from this taxonomy.'), 'lazy' => true]
        );
    }

    /**
     * The installed version against the one shipped in app/files/taxonomies.
     *
     * @param array $taxonomy
     * @param bool $mayUpdate
     * @return array
     */
    public function freshness(array $taxonomy, $mayUpdate)
    {
        $t = $taxonomy['Taxonomy'];
        $installed = (int)$t['version'];
        $shipped = null;
        $path = APP . 'files' . DS . 'taxonomies' . DS . basename($t['namespace']) . DS . 'machinetag.json';
        if (is_readable($path)) {
            try {
                $vocab = FileAccessTool::readJsonFromFile($path);
                if (($vocab['namespace'] ?? null) === $t['namespace']) {
                    $shipped = (int)($vocab['version'] ?? 1);
                }
            } catch (Exception $e) {
                $shipped = null;
            }
        }
        $action = null;
        if ($shipped === null) {
            $state = 'muted';
            $headline = __('Not one of the taxonomies shipped with MISP.');
        } else if ($shipped > $installed) {
            $state = 'warn';
            $headline = __('Version %s is shipped; this instance has version %s.', $shipped, $installed);
            if ($mayUpdate) {
                $action = ['label' => __('Update taxonomies'), 'href' => '/taxonomies/update', 'method' => 'post'];
            }
        } else {
            $state = 'ok';
            $headline = __('Up to date with the shipped version.');
        }
        $items = [['label' => __('Installed'), 'value' => __('Version %s', $installed)]];
        if ($shipped !== null) {
            $items[] = [
                'label' => __('Shipped'),
                'value' => __('Version %s', $shipped),
                'tone' => $shipped > $installed ? 'warn' : null,
            ];
        }
        return RailCard::status('taxonomy-freshness', __('Freshness'), 'fas fa-rotate', $state, $headline, $items, $action);
    }
}
