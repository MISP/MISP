<?php
App::uses('RailCard', 'Tools/RailCards');

/**
 * Rail cards for a noticelist, from its entries as NoticelistsController::view
 * loads them.
 */
class NoticelistRailCards
{
    const FACET_LIMIT = 6;

    /**
     * What makes the list speak up: the attribute types and categories its
     * entries match, and the tags they suggest.
     *
     * @param array $noticelist
     * @return array
     */
    public function fires(array $noticelist)
    {
        $entries = $noticelist['Noticelist']['NoticelistEntry'] ?? [];
        $byField = [];
        $tags = [];
        foreach ($entries as $entry) {
            $data = $entry['data'] ?? [];
            $fields = $this->fields($data);
            foreach (array_unique((array)($data['value'] ?? [])) as $value) {
                foreach ($fields as $field) {
                    $byField[$field][$value] = ($byField[$field][$value] ?? 0) + 1;
                }
            }
            foreach (array_unique((array)($data['tags'] ?? [])) as $tag) {
                $tags[$tag] = ($tags[$tag] ?? 0) + 1;
            }
        }
        $labels = [
            'type' => [__('Attribute types'), 'attribute', 'fas fa-cube'],
            'category' => [__('Categories'), 'category', 'fas fa-folder'],
        ];
        $groups = [];
        foreach ($byField as $field => $values) {
            list($label, $colour, $icon) = $labels[$field] ?? [Inflector::humanize($field), null, 'fas fa-filter'];
            $groups[] = $this->group($field, $label, $icon, $colour, $values, $entries, $field);
        }
        if (!empty($tags)) {
            $groups[] = $this->group('tags', __('Suggested tags'), 'fas fa-tag', 'tag', $tags, $entries);
        }
        $total = count($entries);
        return RailCard::inventory(
            'noticelist-fires',
            __('Where it fires'),
            'fas fa-bell',
            ['count' => $total, 'label' => __n('rule', 'rules', $total)],
            $groups,
            false,
            ['empty' => __('This noticelist has no rule.')]
        );
    }

    /**
     * An object's meta-category is matched against the same values as an
     * attribute's category, so the two count as one field.
     *
     * @param array $data an entry's data
     * @return array
     */
    private function fields(array $data)
    {
        return array_values(array_unique(array_map(function ($field) {
            return $field === 'meta-category' ? 'category' : $field;
        }, (array)($data['field'] ?? []))));
    }

    /**
     * @param string $key
     * @param string $label
     * @param string $icon
     * @param string|null $colour
     * @param array $counts value => rules naming it
     * @param array $entries
     * @param string|null $field count only the rules on this field
     * @return array
     */
    private function group($key, $label, $icon, $colour, array $counts, array $entries, $field = null)
    {
        $rules = 0;
        foreach ($entries as $entry) {
            $data = $entry['data'] ?? [];
            if ($field === null ? !empty($data['tags']) : in_array($field, $this->fields($data), true)) {
                $rules++;
            }
        }
        arsort($counts);
        $facets = [];
        foreach (array_slice($counts, 0, self::FACET_LIMIT, true) as $value => $count) {
            $facets[] = ['label' => (string)$value, 'count' => $count];
        }
        return [
            'key' => $key,
            'label' => $label,
            'icon' => $icon,
            'color' => $colour,
            'count' => $rules,
            'facets' => $facets,
            'more' => max(0, count($counts) - self::FACET_LIMIT),
        ];
    }
}
