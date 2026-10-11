<?php
/**
 * Canonical presentation of MISP's distribution levels.
 *
 * A distribution level is rendered the same way everywhere — the same tint,
 * the same text colour, the same glyph, the same wording — so this table is
 * the single place any of it is decided.
 *
 * Levels mirror MISP's `distribution_level_ids`:
 *   0 your organisation only   3 all communities
 *   1 this community only      4 sharing group
 *   2 connected communities    5 inherit from event
 *
 * Keys per level:
 *   label  translated wording, also used as the badge title attribute
 *   sub    one-line gloss on who that level reaches, for the forms that offer
 *          the levels as cards rather than as a select
 *   bg     badge / icon-frame background (a pale tint)
 *   color  text and glyph colour, also the border at 20% via `%s20`
 *   icon   full class attribute for the glyph (Font Awesome or misp-iconify)
 *
 */

class DistributionLevel
{
    /**
     * Translated presentation table.
     *
     * @return array
     */
    private static function levels()
    {
        return array(
            0 => array(
                'label' => __('Your organisation only'),
                'sub'   => __('Your organisation on this server only'),
                'bg'    => '#f8d7da',
                'color' => '#842029',
                'icon'  => 'fas fa-building',
            ),
            1 => array(
                'label' => __('This community only'),
                'sub'   => __('Every organisation on this server'),
                'bg'    => '#ffe5b4',
                'color' => '#b45309',
                'icon'  => 'fas fa-users',
            ),
            2 => array(
                'label' => __('Connected communities'),
                'sub'   => __('This server and the ones connected to it'),
                'bg'    => '#e7d3c3',
                'color' => '#5a3e2b',
                'icon'  => 'fas fa-network-wired',
            ),
            3 => array(
                'label' => __('All communities'),
                'sub'   => __('Free to propagate from one server to the next'),
                'bg'    => '#d1f7e0',
                'color' => '#0f5132',
                'icon'  => 'fas fa-globe',
            ),
            4 => array(
                'label' => __('Sharing group'),
                'sub'   => __('Any organisation that is part of the selected sharing group'),
                'bg'    => '#dce8ff',
                'color' => '#0e146d',
                'icon'  => 'misp-icon misp-icon-sharing-group misp-simple',
            ),
            5 => array(
                'label' => __('Inherited'),
                'sub'   => __('Follows the distribution of the event'),
                'bg'    => '#e6b7df',
                'color' => '#380f33',
                'icon'  => 'fas fa-code-fork',
            ),
        );
    }

    /**
     * Shown for a level that is null, empty or outside 0-5 — which happens on
     * remote data (server/feed previews) that MISP has not normalised yet.
     *
     * @return array
     */
    public static function fallback()
    {
        return array(
            'label' => __('Unknown'),
            'sub'   => __('This value is not one of MISP\'s distribution levels'),
            'bg'    => '#f1f1f1',
            'color' => '#333',
            'icon'  => 'fas fa-question',
        );
    }

    /**
     * The whole table, keyed by level. Safe to json_encode for the templates
     * that render distribution badges client-side.
     *
     * @return array level => array(label, sub, bg, color, icon)
     */
    public static function all()
    {
        return self::levels();
    }

    /**
     * One level, falling back to the unknown entry so a caller never has to
     * write its own `?? [...]` default.
     *
     * @param mixed $level
     * @return array array(label, sub, bg, color, icon)
     */
    public static function get($level)
    {
        $levels = self::levels();
        if ($level === null || $level === '' || !isset($levels[(int)$level])) {
            return self::fallback();
        }
        return $levels[(int)$level];
    }
}
