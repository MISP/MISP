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
 *   bg     badge / icon-frame background (a pale tint)
 *   color  text and glyph colour, also the border at 20% via `%s20`
 *   icon   full class attribute for the glyph (Font Awesome or misp-iconify)
 *
 */

class DistributionLevel
{
    /**
     * Raw table. Labels are plain English here because __() cannot run in a
     * property initialiser; they are translated on the way out.
     *
     * @var array
     */
    private static $levels = array(
        0 => array(
            'label' => 'Your organisation only',
            'bg'    => '#f8d7da',
            'color' => '#842029',
            'icon'  => 'fas fa-building',
        ),
        1 => array(
            'label' => 'This community only',
            'bg'    => '#ffe5b4',
            'color' => '#b45309',
            'icon'  => 'fas fa-users',
        ),
        2 => array(
            'label' => 'Connected communities',
            'bg'    => '#e7d3c3',
            'color' => '#5a3e2b',
            'icon'  => 'fas fa-network-wired',
        ),
        3 => array(
            'label' => 'All communities',
            'bg'    => '#d1f7e0',
            'color' => '#0f5132',
            'icon'  => 'fas fa-globe',
        ),
        4 => array(
            'label' => 'Sharing group',
            'bg'    => '#dce8ff',
            'color' => '#0e146d',
            'icon'  => 'misp-icon misp-icon-sharing-group misp-simple',
        ),
        5 => array(
            'label' => 'Inherited',
            'bg'    => '#e6b7df',
            'color' => '#380f33',
            'icon'  => 'fas fa-code-fork',
        ),
    );

    /**
     * Shown for a level that is null, empty or outside 0-5 — which happens on
     * remote data (server/feed previews) that MISP has not normalised yet.
     *
     * @var array
     */
    private static $unknown = array(
        'label' => 'Unknown',
        'bg'    => '#f1f1f1',
        'color' => '#333',
        'icon'  => 'fas fa-question',
    );

    /**
     * The whole table, keyed by level. Safe to json_encode for the templates
     * that render distribution badges client-side.
     *
     * @return array level => array(label, bg, color, icon)
     */
    public static function all()
    {
        $out = array();
        foreach (self::$levels as $level => $meta) {
            $meta['label'] = __($meta['label']);
            $out[$level] = $meta;
        }
        return $out;
    }

    /**
     * One level, falling back to the unknown entry so a caller never has to
     * write its own `?? [...]` default.
     *
     * @param mixed $level
     * @return array array(label, bg, color, icon)
     */
    public static function get($level)
    {
        if ($level === null || $level === '' || !isset(self::$levels[(int)$level])) {
            return self::fallback();
        }
        $meta = self::$levels[(int)$level];
        $meta['label'] = __($meta['label']);
        return $meta;
    }

    /**
     * @return array the unknown-level entry
     */
    public static function fallback()
    {
        $meta = self::$unknown;
        $meta['label'] = __($meta['label']);
        return $meta;
    }
}
