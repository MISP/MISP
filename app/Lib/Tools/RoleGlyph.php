<?php
/**
 * Canonical presentation of a MISP role.
 *
 * **Keyed by name, on purpose.** A role is a user-defined record, not a fixed
 * scale like a distribution level, so there is no id to key on. Its permission
 * flags would be the honest discriminator, but every caller holds a different
 * subset of them — the users index contains four flags, the forms only receive
 * `id => name` — so a flag-based lookup would classify the same role
 * differently depending on who asked. The name is the one field they all have.
 * MISP's six default roles are listed here; anything else is a custom role and
 * gets the `custom` entry, which is what the theme already showed.
 *
 * Keys per entry:
 *   icon     full class attribute for the glyph, as DistributionLevel gives it
 *   colour   hex ink for the glyph. A mid-tone rather than `--bs-<variant>`:
 *            it has to read against its own tint over a light row and over a
 *            dark one, which `warning` at full brightness does not, so it is
 *            written out here rather than read from CSS
 *   tint     that ink at 12% — an rgba(), so the badge picks up whatever
 *            surface it sits on instead of forcing a pale one
 *
 * @see RoleGlyphHelper for the view-side wrapper
 */

class RoleGlyph
{
    /**
     * MISP's default roles, by the name each one ships with.
     *
     * @var array
     */
    private static $roles = array(
        'admin' => array(
            'icon'    => 'fas fa-shield-halved',
            'colour'  => '#B02A37',
        ),
        'org admin' => array(
            'icon'    => 'fas fa-user-shield',
            'colour'  => '#106B84',
        ),
        'sync user' => array(
            'icon'    => 'fas fa-arrows-rotate',
            'colour'  => '#B45309',
        ),
        'publisher' => array(
            'icon'    => 'fas fa-upload',
            'colour'  => '#0F5132',
        ),
        'read only' => array(
            'icon'    => 'fas fa-book-open-reader',
            'colour'  => '#6D28D9',
        ),
        'user' => array(
            'icon'    => 'fas fa-user',
            'colour'  => '#5A6675',
        ),
    );

    /**
     * Any role an administrator defined themselves.
     *
     * @var array
     */
    private static $custom = array(
        'icon'    => 'fas fa-user-pen',
        'colour'  => '#41464B',
    );

    /** Opacity of the tint behind a glyph drawn in the role's own colour. */
    const TINT_ALPHA = .12;

    /**
     * @param string|array $role role name, or a role record carrying `name`
     * @return array array(icon, colour, tint)
     */
    public static function get($role)
    {
        $name = is_array($role)
            ? (isset($role['name']) ? $role['name'] : '')
            : (string)$role;
        $key = strtolower(trim($name));

        return self::expand(
            isset(self::$roles[$key]) ? self::$roles[$key] : self::$custom
        );
    }

    /**
     * The whole table, keyed by the lowercased default name, plus 'custom'.
     * For the callers that hand it to JavaScript rather than looking one up.
     *
     * @return array
     */
    public static function all()
    {
        $out = array();
        foreach (self::$roles as $key => $meta) {
            $out[$key] = self::expand($meta);
        }
        $out['custom'] = self::expand(self::$custom);

        return $out;
    }

    /**
     * @return array the custom-role entry
     */
    public static function fallback()
    {
        return self::expand(self::$custom);
    }

    /**
     * Fills in the one derived key, so the table holds a colour once.
     *
     * @param array $meta
     * @return array
     */
    private static function expand(array $meta)
    {
        $meta['tint'] = self::tint($meta['colour'], self::TINT_ALPHA);

        return $meta;
    }

    /**
     * `#B02A37` at 12% becomes `rgba(176, 42, 55, 0.12)`. An rgba() rather than
     * a second hex because the badge is drawn over whatever the surface is.
     *
     * @param string $hex
     * @param float $alpha
     * @return string
     */
    private static function tint($hex, $alpha)
    {
        $raw = ltrim($hex, '#');
        if (strlen($raw) === 3) {
            $raw = $raw[0] . $raw[0] . $raw[1] . $raw[1] . $raw[2] . $raw[2];
        }

        return sprintf(
            'rgba(%d, %d, %d, %s)',
            hexdec(substr($raw, 0, 2)),
            hexdec(substr($raw, 2, 2)),
            hexdec(substr($raw, 4, 2)),
            $alpha
        );
    }
}
