<?php

/**
 * The "More filters" panel of the attribute and object indexes.
 *
 * One list, so that a filter sits at the same place on the global attribute
 * index, an event's attribute tab and its object tab. Each one says where it
 * is offered: related events and feed hits are worked out in PHP, which an
 * event can afford but the instance-wide index cannot, and keeping only the
 * warninglist hits there would mean reading the whole instance.
 */
class AttributeFilterPanel
{
    /**
     * @param array $options view var name => [value => label], as set by the
     *              controller; a filter whose list is missing or empty is left
     *              out (e.g. Creator Org outside an extended event view)
     * @param bool $inEvent false on the instance-wide index
     * @param array $leading object-level controls drawn before the shared ones
     * @return array filter_bar `more_filters` children
     */
    public static function children(array $options, $inEvent, array $leading = [])
    {
        $any = ['' => __('Any')];
        $yesNo = $any + ['1' => __('Yes'), '2' => __('No')];
        $filters = array_merge($leading, [
            ['name' => 'category', 'label' => __('Category'), 'options' => $options['categoryOptions'] ?? null, 'col' => 3],
            ['name' => 'type', 'label' => __('Type'), 'options' => $options['typeOptions'] ?? null, 'col' => 3],
            ['name' => 'org', 'label' => __('Creator Org'), 'options' => $options['orgOptions'] ?? null],
            ['name' => 'tags', 'label' => __('Tags'), 'options' => $options['tagOptions'] ?? null],
            ['name' => 'galaxy', 'label' => __('Galaxy'), 'options' => $options['galaxyOptions'] ?? null],
            ['name' => 'toIDS', 'label' => __('IDS'), 'options' => $yesNo],
            ['name' => 'correlation', 'label' => __('Related events'), 'options' => $inEvent ? $yesNo : null],
            ['name' => 'feed', 'label' => __('Feed hits'), 'options' => $inEvent ? $yesNo : null],
            ['name' => 'analystData', 'label' => __('Analyst data'), 'options' => $yesNo],
            ['name' => 'warning', 'label' => __('Matches a warninglist'), 'options' => $inEvent ? $yesNo : $any + ['2' => __('No')]],
        ]);
        $children = [];
        foreach ($filters as $filter) {
            if (empty($filter['options'])) {
                continue;
            }
            $children[] = [
                'type' => 'dropdown',
                'label' => $filter['label'],
                'name' => $filter['name'],
                // The empty option's label is the control's placeholder
                'options' => $any + $filter['options'],
                'col' => $filter['col'] ?? 2,
            ];
        }
        return $children;
    }
}
