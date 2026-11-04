<?php
/**
 * Canonical presentation of the accent a modal is dressed in.
 *
 * Every add/edit modal in the Overmind theme is the same shape — an accented
 * header strip, an accented section label per field group, an accented submit
 * button — and only the accent changes between them. Before this table each
 * template inlined its own version of it, which is how the theme ended up with
 * `var(--primary)` next to `var(--bs-primary)`, a tint written both as
 * `rgba(24,146,177,.06)` and `#97CC040f`, and a glyph at three different
 * opacities.
 *
 * An accent key is a *scope* name, not a colour: 'tag', 'galaxy', 'event'. The
 * solid colour of a scope lives in CSS (bootstrap5-custom.min.css builds the
 * `$theme-colors` map; mainOvermind.css adds the rest), so this table points at
 * the CSS custom property rather than restating the hash. `hex` is only the
 * fallback for the accents CSS has no variable for, and the value to hand to
 * JavaScript when a template has to draw a swatch itself.
 *
 * Keys per accent, all ready to drop into a template:
 *   colour     colour expression for text, borders and glyphs
 *   tint       header-strip background — a 6% wash of the accent
 *   line       header-strip bottom border
 *   textClass  Bootstrap text utility, '' when the scope has none
 *   textStyle  inline `color:` declaration, '' when textClass covers it
 *   btnClass   full class attribute of the submit button
 *   btnStyle   inline declarations for the submit button, '' when btnClass covers it
 *   hex        the raw colour, for JavaScript and for computing tints
 *
 * @see ModalAccentHelper for the view-side wrapper
 */
class ModalAccent
{
    /**
     * Accents that Bootstrap knows as theme colours. Each one gets
     * `--bs-<key>`, `--bs-<key>-rgb`, `.text-<key>`, `.bg-<key>` and
     * `.btn-<key>` for free, so nothing but the key is needed here.
     *
     * `text` overrides the text utility: `warning` is too pale to read as
     * `.text-warning` on a light strip, so it uses Bootstrap's emphasis variant.
     *
     * `white` marks the accents whose submit button carries `text-white`. It
     * records what the theme ships rather than what a contrast checker would
     * pick — Bootstrap's own auto-contrast puts black on most of these, and
     * flipping them is a design change, not a refactor. `primary` is absent
     * because mainOvermind.css already forces `.btn-primary` white.
     *
     * @var array
     */
    private static $themeColours = array(
        'primary'     => array(),
        'secondary'   => array(),
        'success'     => array(),
        'info'        => array(),
        'warning'     => array('text' => 'text-warning-emphasis'),
        'danger'      => array('white' => true),
        'event'       => array('white' => true),
        'object'      => array('white' => true),
        'attribute'   => array('white' => true),
        'tag'         => array('white' => true),
        'galaxy'      => array('white' => true),
        'report'      => array('white' => true),
        'sighting'    => array('white' => true),
        'correlation' => array(),
        'category'    => array('white' => true),
        'type'        => array(),
        'analystData' => array('white' => true),
        'enrichment'  => array('white' => true),
    );

    /**
     * Accents CSS defines outside Bootstrap's theme map, plus the handful that
     * live nowhere but here. Without a `--bs-<key>-rgb` there is no variable to
     * build a tint from, so these carry their hash and the tint is computed.
     *
     * @var array
     */
    private static $customColours = array(
        // mainOvermind.css: --warninglist / --warninglist-soft
        'warninglist' => array(
            'hex'  => '#9D174D',
            'var'  => '--warninglist',
            'tint' => 'var(--warninglist-soft)',
        ),
        // The attachment upload form, the one accent with no CSS presence at
        // all. Its wash is heavier than the 6% standard and its rule is the
        // accent at 85% rather than solid — kept as it shipped.
        'attachment' => array(
            'hex'   => '#F59E0B',
            'alpha' => .08,
            'line'  => 'rgba(245, 158, 11, .85)',
        ),
    );

    /** Opacity of the header strip's wash over the page background. */
    const TINT_ALPHA = .06;

    /**
     * @param string $accent accent key; unknown keys fall back to 'primary'
     * @return array see the class comment for the keys
     */
    public static function get($accent)
    {
        $key = (string)$accent;
        if ($key === '' || (!isset(self::$themeColours[$key]) && !isset(self::$customColours[$key]))) {
            $key = 'primary';
        }

        return isset(self::$themeColours[$key])
            ? self::themeAccent($key)
            : self::customAccent($key);
    }

    /**
     * @return array every accent key this table knows, in declaration order
     */
    public static function keys()
    {
        return array_merge(
            array_keys(self::$themeColours),
            array_keys(self::$customColours)
        );
    }

    /**
     * Bootstrap theme colour: the utilities exist, so lean on them entirely and
     * let CSS stay the authority on the actual colour.
     *
     * @param string $key
     * @return array
     */
    private static function themeAccent($key)
    {
        $config = self::$themeColours[$key];
        $white = !empty($config['white']);

        return array(
            'key'       => $key,
            'colour'    => sprintf('var(--bs-%s)', $key),
            'tint'      => sprintf('rgba(var(--bs-%s-rgb), %s)', $key, self::TINT_ALPHA),
            'line'      => sprintf('var(--bs-%s)', $key),
            'textClass' => isset($config['text']) ? $config['text'] : 'text-' . $key,
            'textStyle' => '',
            'btnClass'  => 'btn-' . $key . ($white ? ' text-white' : ''),
            'btnStyle'  => '',
            'badgeClass' => 'bg-' . $key,
            'badgeStyle' => '',
            'hex'       => isset($config['hex']) ? $config['hex'] : null,
        );
    }

    /**
     * Accent outside Bootstrap's map: no `.text-*` or `.btn-*` to reach for, so
     * the colour is applied inline.
     *
     * @param string $key
     * @return array
     */
    private static function customAccent($key)
    {
        $config = self::$customColours[$key];
        $hex = $config['hex'];
        $colour = isset($config['var']) ? sprintf('var(%s)', $config['var']) : $hex;
        $alpha = isset($config['alpha']) ? $config['alpha'] : self::TINT_ALPHA;

        return array(
            'key'       => $key,
            'colour'    => $colour,
            'tint'      => isset($config['tint']) ? $config['tint'] : self::tint($hex, $alpha),
            'line'      => isset($config['line']) ? $config['line'] : $colour,
            'textClass' => '',
            'textStyle' => sprintf('color:%s;', $colour),
            'btnClass'  => 'text-white',
            'btnStyle'  => sprintf('background:%s; border-color:%s;', $colour, $colour),
            'badgeClass' => '',
            'badgeStyle' => sprintf('background:%s;', $colour),
            'hex'       => $hex,
        );
    }

    /**
     * `#9D174D` at 6% becomes `rgba(157, 23, 77, .06)` — used only for the
     * accents with no `--bs-<key>-rgb` to feed the same expression.
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
