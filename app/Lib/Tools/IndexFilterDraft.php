<?php

/**
 * The one description of a deferred-apply filter panel.
 *
 * Two bars draw one: Elements/Logs/filter_card.ctp for the log indexes and
 * genericElementsBS5/IndexTable/filter_bar.ctp for any scaffolded index that
 * declares a `more_filters` control. They share the markup through
 * `IndexTable/filter_toggle` + `IndexTable/filter_panel`, the behaviour
 * through initIndexFilterDraft() in mispOvermind.js, and the wording here.
 *
 * The strings live in PHP rather than in the JS engine because MISP
 * translates in PHP; a default baked into mispOvermind.js would ship
 * untranslated.
 */
class IndexFilterDraft
{
    /**
     * Wording for the draft summary, handed to initIndexFilterDraft() as its
     * `strings` option. `%s` in pendingMany is the number of changes.
     *
     * @param array $overrides keys to replace, for a bar that needs its own
     * @return array
     */
    public static function strings(array $overrides = [])
    {
        return $overrides + [
            'searchLabel' => __('Search'),
            'apply' => __('Apply filters'),
            'applied' => __('Filters applied'),
            'pendingOne' => __('1 change not applied yet'),
            'pendingMany' => __('%s changes not applied yet'),
            'noFilter' => __('No filter — showing every entry.'),
            'clearAll' => __('Clear all'),
            'remove' => __('Remove this filter'),
            'willBeRemoved' => __('Will be removed'),
            'notApplied' => __('Not applied yet'),
            'loadError' => __('Could not load the filtered results. Please try again.'),
        ];
    }

    /**
     * The same wording as a JSON literal, ready to drop into a <script>.
     *
     * @param array $overrides
     * @return string
     */
    public static function stringsJson(array $overrides = [])
    {
        return json_encode(self::strings($overrides), JSON_UNESCAPED_UNICODE);
    }
}
