<?php

/**
 * Whether a warninglist hit means shared infrastructure (`known`) or a
 * likely false positive. Each list declares its own `category` upstream;
 * an analyst profile can override it per list name.
 */
class WarninglistCategory
{
    /** The column's own default, and the fall-through. */
    const FALSE_POSITIVE = 'false_positive';

    const KNOWN = 'known';

    /**
     * What `warninglists.category` validates against, so anything offering
     * a choice of category offers exactly this.
     */
    const CATEGORIES = array(self::KNOWN, self::FALSE_POSITIVE);

    /** Where an answer came from, carried per hit. */
    const SOURCE_PROFILE = 'profile';
    const SOURCE_LIST = 'list';
    const SOURCE_DEFAULT = 'default';

    /**
     * The profile's map, keyed by exact warninglist name, then the list's
     * own `warninglists.category`, then `false_positive`.
     *
     * @param string|null $name
     * @param string|null $column `warninglists.category` for this list
     * @param array $overrides The profile's `warninglist_category` map
     * @return array `category` and `source`
     */
    public static function resolve($name, $column,
        array $overrides = array()
    ) {
        $key = (string)$name;
        if (isset($overrides[$key])
            && self::valid($overrides[$key])
        ) {
            return array(
                'category' => (string)$overrides[$key],
                'source' => self::SOURCE_PROFILE,
            );
        }
        if (self::valid($column)) {
            return array(
                'category' => (string)$column,
                'source' => self::SOURCE_LIST,
            );
        }
        return array(
            'category' => self::FALSE_POSITIVE,
            'source' => self::SOURCE_DEFAULT,
        );
    }

    /**
     * Whether a category is one MISP admits. A profile override naming
     * anything else is ignored and falls through.
     *
     * @param mixed $category
     * @return bool
     */
    public static function valid($category)
    {
        return $category === self::KNOWN
            || $category === self::FALSE_POSITIVE;
    }

    /**
     * What a category does and does not claim, in prose.
     *
     * **This is the signal on the page most routinely read backwards**,
     * and the band that carries it exists to say so
     * (`value_verdict_warninglist.ctp`). A hit is not a verdict about
     * the organisations that reported the value: `known` says an action
     * against this value will land on unrelated services too, and
     * `false_positive` says reports about it are usually collateral.
     * Neither says the reporting was wrong, and both sentences end by
     * saying that outright.
     *
     * A category with no note gets none rather than a guessed one.
     *
     * @param string|null $category
     * @return string|null
     */
    public static function note($category)
    {
        if ($category === self::KNOWN) {
            return __(
                'Category `known`: widely used infrastructure, not a'
                . ' false positive. Blocking it would also hit unrelated'
                . ' services; the reports are not wrong.'
            );
        }
        if ($category === self::FALSE_POSITIVE) {
            return __(
                'Category `false_positive`: this value often shows up'
                . ' in real incidents without being the indicator. The'
                . ' organisations that reported it are not wrong.'
            );
        }
        return null;
    }
}
