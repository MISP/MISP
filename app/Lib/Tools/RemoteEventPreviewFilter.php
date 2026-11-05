<?php
App::uses('AttributeFilterPanel', 'Tools');

/**
 * The filters of a remote event preview's Attributes and Objects tabs. A
 * feed's or a remote instance's event is downloaded whole, so its tabs
 * filter the rows they hold instead of querying; the keys and values are
 * the event tabs' own (`type` a comma list, the yes/no filters 1 or 2).
 */
class RemoteEventPreviewFilter
{
    const ATTRIBUTE_FILTERS = ['category', 'type', 'tags', 'toIDS', 'warning'];

    const OBJECT_FILTERS = ['name', 'meta-category', 'category', 'type', 'tags', 'toIDS'];

    /**
     * The filters set among the request's named parameters.
     *
     * @param array $named
     * @param array $names one of the *_FILTERS lists
     * @return array name => value, `searchFor` included
     */
    public static function active(array $named, array $names)
    {
        $active = [];
        foreach (array_merge(['searchFor'], $names) as $name) {
            if (isset($named[$name]) && is_string($named[$name]) && trim($named[$name]) !== '') {
                $active[$name] = trim($named[$name]);
            }
        }
        return $active;
    }

    /**
     * The Filters panel children for the rows on hand, each list holding
     * only what the event carries.
     *
     * @param array $attributes every attribute the tab filters on
     * @param array $objects the objects, for the Objects tab
     * @param array $names one of the *_FILTERS lists
     * @return array filter_bar children
     */
    public static function children(array $attributes, array $objects, array $names)
    {
        $values = ['category' => [], 'type' => [], 'tags' => [], 'name' => [], 'meta-category' => []];
        foreach ($attributes as $attribute) {
            foreach (['category', 'type'] as $field) {
                if (!empty($attribute[$field])) {
                    $values[$field][$attribute[$field]] = $attribute[$field];
                }
            }
            foreach (self::tagNames($attribute) as $tag) {
                $values['tags'][$tag] = $tag;
            }
        }
        foreach ($objects as $object) {
            foreach (['name', 'meta-category'] as $field) {
                if (!empty($object[$field])) {
                    $values[$field][$object[$field]] = $object[$field];
                }
            }
        }
        foreach ($values as &$list) {
            ksort($list, SORT_NATURAL | SORT_FLAG_CASE);
        }
        unset($list);

        $leading = [];
        if (in_array('name', $names, true)) {
            $leading[] = ['name' => 'name', 'label' => __('Template'), 'options' => $values['name'], 'col' => 3, 'group' => __('Object')];
            $leading[] = ['name' => 'meta-category', 'label' => __('Meta-category'), 'options' => $values['meta-category'], 'col' => 3, 'group' => __('Object')];
        }
        $children = [];
        foreach (AttributeFilterPanel::children([
            'categoryOptions' => $values['category'],
            'typeOptions' => $values['type'],
            'tagOptions' => $values['tags'],
        ], true, $leading) as $filter) {
            if (in_array($filter['name'], $names, true)) {
                $children[] = $filter + ($filter['name'] === 'type' ? ['separator' => ','] : []);
            }
        }
        return $children;
    }

    /**
     * @param array $attributes
     * @param array $filters as active() returns them
     * @return array the matching attributes
     */
    public static function attributes(array $attributes, array $filters)
    {
        return array_values(array_filter($attributes, function ($attribute) use ($filters) {
            return self::matches($attribute, $filters);
        }));
    }

    /**
     * The objects matching the object filters and holding at least one
     * attribute that matches the attribute filters. The search also reads
     * the object's own name, meta-category and comment.
     *
     * @param array $objects
     * @param array $filters as active() returns them
     * @return array
     */
    public static function objects(array $objects, array $filters)
    {
        $attributeFilters = array_diff_key($filters, array_flip(['name', 'meta-category', 'searchFor']));
        $search = $filters['searchFor'] ?? null;
        return array_values(array_filter($objects, function ($object) use ($filters, $attributeFilters, $search) {
            foreach (['name', 'meta-category'] as $field) {
                if (isset($filters[$field]) && (string)($object[$field] ?? '') !== $filters[$field]) {
                    return false;
                }
            }
            $own = $search !== null && self::contains([
                $object['name'] ?? '', $object['meta-category'] ?? '', $object['comment'] ?? '', $object['uuid'] ?? '',
            ], $search);
            if ($own && empty($attributeFilters)) {
                return true;
            }
            $wanted = $attributeFilters + ($own || $search === null ? [] : ['searchFor' => $search]);
            if (empty($wanted)) {
                return true;
            }
            foreach ($object['Attribute'] ?? [] as $attribute) {
                if (self::matches($attribute, $wanted)) {
                    return true;
                }
            }
            return false;
        }));
    }

    private static function matches(array $attribute, array $filters)
    {
        if (isset($filters['searchFor']) && !self::contains([
            $attribute['value'] ?? '', $attribute['comment'] ?? '', $attribute['uuid'] ?? '',
        ], $filters['searchFor'])) {
            return false;
        }
        if (isset($filters['category']) && (string)($attribute['category'] ?? '') !== $filters['category']) {
            return false;
        }
        if (isset($filters['type']) && !in_array((string)($attribute['type'] ?? ''), explode(',', $filters['type']), true)) {
            return false;
        }
        if (isset($filters['tags']) && !in_array($filters['tags'], self::tagNames($attribute), true)) {
            return false;
        }
        $flags = [
            'toIDS' => !empty($attribute['to_ids']),
            'warning' => !empty($attribute['warnings']),
        ];
        foreach ($flags as $name => $set) {
            if (isset($filters[$name]) && in_array($filters[$name], ['1', '2'], true) && $set !== ($filters[$name] === '1')) {
                return false;
            }
        }
        return true;
    }

    private static function contains(array $haystacks, $needle)
    {
        foreach ($haystacks as $haystack) {
            if (mb_stripos((string)$haystack, $needle) !== false) {
                return true;
            }
        }
        return false;
    }

    /**
     * An attribute's tag names, from `Tag` rows as MISP JSON carries them or
     * from `AttributeTag` rows carrying Tag.
     */
    private static function tagNames(array $attribute)
    {
        $names = [];
        foreach (array_merge($attribute['Tag'] ?? [], $attribute['AttributeTag'] ?? []) as $tag) {
            $name = $tag['Tag']['name'] ?? $tag['name'] ?? null;
            if ($name !== null && $name !== '') {
                $names[] = $name;
            }
        }
        return $names;
    }
}
