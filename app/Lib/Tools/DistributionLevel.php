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
 *   token  the level's --misp-<token>-bg/-fg/-border theme properties; see
 *          themed() for drawing a colour a theme can replace
 *
 */

class DistributionLevel
{
    /**
     * Raw table. Labels and subs are plain English here because __() cannot run
     * in a property initialiser; they are translated on the way out.
     *E
     *
     * @var array
     */
    private static $levels = array(
        0 => array(
            'token' => 'dist-0',
            'label' => 'Your organisation only',
            'sub'   => 'Your organisation on this server only',
            'bg'    => '#f8d7da',
            'color' => '#842029',
            'icon'  => 'fas fa-building',
        ),
        1 => array(
            'token' => 'dist-1',
            'label' => 'This community only',
            'sub'   => 'Every organisation on this server',
            'bg'    => '#ffe5b4',
            'color' => '#b45309',
            'icon'  => 'fas fa-users',
        ),
        2 => array(
            'token' => 'dist-2',
            'label' => 'Connected communities',
            'sub'   => 'This server and the ones connected to it',
            'bg'    => '#e7d3c3',
            'color' => '#5a3e2b',
            'icon'  => 'fas fa-network-wired',
        ),
        3 => array(
            'token' => 'dist-3',
            'label' => 'All communities',
            'sub'   => 'Free to propagate from one server to the next',
            'bg'    => '#d1f7e0',
            'color' => '#0f5132',
            'icon'  => 'fas fa-globe',
        ),
        4 => array(
            'token' => 'dist-4',
            'label' => 'Sharing group',
            'sub'   => 'Any organisation that is part of the selected sharing group',
            'bg'    => '#dce8ff',
            'color' => '#0e146d',
            'icon'  => 'misp-icon misp-icon-sharing-group misp-simple',
        ),
        5 => array(
            'token' => 'dist-5',
            'label' => 'Inherited',
            'sub'   => 'Follows the distribution of the event',
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
        'token' => 'dist-unknown',
        'label' => 'Unknown',
        'sub'   => 'This value is not one of MISP\'s distribution levels',
        'bg'    => '#f1f1f1',
        'color' => '#333',
        'icon'  => 'fas fa-question',
    );

    /**
     * The levels that reach fewer people than $level. 0-3 widen in order; a
     * sharing group is narrower than "connected" or "all communities" but
     * cannot be ranked against "this community only" or another group.
     *
     * @param mixed $level
     * @return array
     */
    public static function narrowerThan($level)
    {
        $narrower = array(
            0 => array(),
            1 => array(0),
            2 => array(0, 1, 4),
            3 => array(0, 1, 2, 4),
            4 => array(0),
        );
        return $narrower[(int)$level] ?? array();
    }

    /**
     * The whole table, keyed by level. Safe to json_encode for the templates
     * that render distribution badges client-side.
     *
     * @return array level => array(label, sub, bg, color, icon)
     */
    public static function all()
    {
        $out = array();
        foreach (self::$levels as $level => $meta) {
            $out[$level] = self::translate($meta);
        }
        return $out;
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
        if ($level === null || $level === '' || !isset(self::$levels[(int)$level])) {
            return self::fallback();
        }
        return self::translate(self::$levels[(int)$level]);
    }

    /**
     * @return array the unknown-level entry
     */
    public static function fallback()
    {
        return self::translate(self::$unknown);
    }

    /**
     * A colour of an entry as the theme's token, falling back to the value
     * in this table: 'bg', 'fg' (the text colour) or 'border', which is the
     * text colour with $alpha (a hex alpha such as '20') appended.
     *
     * @param array $meta an entry from get(), all() or fallback()
     * @param string $role bg, fg or border
     * @param string $alpha
     * @return string
     */
    public static function themed(array $meta, $role, $alpha = '')
    {
        $value = $role === 'bg' ? $meta['bg'] : $meta['color'];
        if ($role === 'border') {
            $value .= $alpha;
        }
        return sprintf('var(--misp-%s-%s, %s)', $meta['token'], $role, $value);
    }

    /**
     * The two human-readable keys of an entry, on their way out of the table.
     *
     * @param array $meta
     * @return array
     */
    private static function translate(array $meta)
    {
        $meta['label'] = __($meta['label']);
        $meta['sub'] = __($meta['sub']);
        return $meta;
    }
}
