<?php
App::uses('RailCard', 'Tools/RailCards');

/**
 * Rail cards for a collection, built from the view's elements once
 * CollectionElement::attachTargets() has run. An element whose target did
 * not come back is one the user cannot read, and is left out.
 */
class CollectionRailCards
{
    const FACET_LIMIT = 6;
    const SOURCE_LIMIT = 6;

    /**
     * @param array $elements Collection.CollectionElement, targets attached
     * @return array
     */
    public function inventory(array $elements)
    {
        $groups = [];
        $total = 0;
        foreach ($elements as $element) {
            $type = $element['element_type'] ?? null;
            $facet = $this->facetOf($element);
            if ($facet === false) {
                continue;
            }
            $total++;
            if (!isset($groups[$type])) {
                list($label, $icon, $color) = $this->typeLabel($type);
                $groups[$type] = [
                    'key' => $type,
                    'label' => $label,
                    'icon' => $icon,
                    'color' => $color,
                    'count' => 0,
                    'filter' => ['element_type' => $type],
                    'facets' => [],
                ];
            }
            $groups[$type]['count']++;
            if ($facet !== null) {
                $groups[$type]['facets'][$facet] = ($groups[$type]['facets'][$facet] ?? 0) + 1;
            }
        }
        $order = array_flip(['Event', 'Attribute', 'Object', 'GalaxyCluster', 'AttributeValue']);
        uksort($groups, function ($a, $b) use ($order) {
            return ($order[$a] ?? 99) <=> ($order[$b] ?? 99);
        });
        foreach ($groups as $type => $group) {
            arsort($group['facets']);
            $facets = [];
            foreach ($group['facets'] as $label => $count) {
                $facets[] = [
                    'label' => (string)$label,
                    'count' => $count,
                    'filter' => ['element_type' => $type, 'facet' => (string)$label],
                ];
            }
            $groups[$type]['partition'] = !empty($facets)
                && array_sum(array_column($facets, 'count')) === $group['count'];
            $groups[$type]['facets'] = array_slice($facets, 0, self::FACET_LIMIT);
            $groups[$type]['more'] = max(0, count($facets) - self::FACET_LIMIT);
        }
        return RailCard::inventory(
            'collection-inventory',
            __('Inventory'),
            'fas fa-boxes-stacked',
            ['count' => $total, 'label' => __n('element', 'elements', $total)],
            array_values($groups),
            true,
            [
                'link' => ['label' => __('Elements'), 'href' => '#tab-elements'],
                'empty' => __('This collection has no elements yet.'),
            ]
        );
    }

    /**
     * The events the collection's elements come from, most represented first.
     *
     * @param array $elements Collection.CollectionElement, targets attached
     * @return array
     */
    public function sources(array $elements)
    {
        $events = [];
        foreach ($elements as $element) {
            $type = $element['element_type'] ?? null;
            if ($type === 'Event' && !empty($element['Event']['id'])) {
                $event = $element['Event'];
            } else if (($type === 'Attribute' || $type === 'Object') && !empty($element[$type]['Event']['id'])) {
                $event = $element[$type]['Event'];
            } else {
                continue;
            }
            $id = (int)$event['id'];
            if (!isset($events[$id])) {
                $events[$id] = ['info' => $event['info'] ?? '', 'count' => 0];
            }
            $events[$id]['count']++;
        }
        uasort($events, function ($a, $b) {
            return $b['count'] <=> $a['count'];
        });
        $rows = [];
        foreach (array_slice($events, 0, self::SOURCE_LIMIT, true) as $id => $event) {
            $rows[] = [
                'label' => $event['info'],
                'href' => '/events/view/' . $id,
                'icon' => 'misp-icon misp-icon-event misp-simple',
                'meta' => ['#' . $id],
                'count' => $event['count'],
            ];
        }
        $hidden = count($events) - count($rows);
        return RailCard::rows(
            'collection-sources',
            __('Source events'),
            'misp-icon misp-icon-event misp-simple',
            $rows,
            $hidden > 0 ? ['label' => __n('%s more event', '%s more events', $hidden, $hidden)] : null,
            ['empty' => __('No element comes from an event.')]
        );
    }

    /**
     * @param array $element
     * @return string|null|false the facet label, null for a type without
     *                           facets, false when the target is unreadable
     */
    private function facetOf(array $element)
    {
        $type = $element['element_type'] ?? null;
        switch ($type) {
            case 'AttributeValue':
                return empty($element['AttributeValue']) ? false : null;
            case 'Event':
                return empty($element['Event']) ? false : null;
            case 'Attribute':
                return empty($element['Attribute']) ? false : $element['Attribute']['type'];
            case 'Object':
                return empty($element['Object']) ? false : $element['Object']['name'];
            case 'GalaxyCluster':
                if (empty($element['GalaxyCluster'][0])) {
                    return false;
                }
                $cluster = $element['GalaxyCluster'][0];
                return $cluster['Galaxy']['name'] ?? $cluster['type'] ?? null;
        }
        return false;
    }

    private function typeLabel($type)
    {
        switch ($type) {
            case 'Event':
                return [__('Events'), 'misp-icon misp-icon-event misp-simple', 'event'];
            case 'Attribute':
                return [__('Attributes'), 'misp-icon misp-icon-attribute misp-simple', 'attribute'];
            case 'Object':
                return [__('Objects'), 'misp-icon misp-icon-object misp-simple', 'object'];
            case 'GalaxyCluster':
                return [__('Galaxy clusters'), 'misp-icon misp-icon-galaxy misp-simple', 'galaxy'];
            case 'AttributeValue':
                return [__('Values'), 'misp-icon misp-icon-value-intelligence misp-simple', 'valueIntelligence'];
        }
        return [$type, null, null];
    }
}
