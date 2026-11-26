<?php
/**
 * Canonical presentation of an export format.
 *
 * The theme shows the list of export formats on three surfaces, and each one
 * received its keys from a different place, spelling the same format three
 * ways: `openIOC` in the per-event download list, `openioc` in the restSearch
 * export modal, `stix_xml` here and `stix` there, `csv_sig` / `csv_all` /
 * `csv_with_context` / `csv` for what is one CSV glyph. `Events/export.ctp`
 * carried its own `$formatStyles` hash for the thirteen it knew, and the other
 * two surfaces drew the same download arrow for every row.
 *
 * So the lookup normalises before it matches: lowercased, `-` and `_` folded
 * away, then an alias table for the handful of genuine synonyms. A format
 * nobody listed here still gets a glyph — `fallback()`, a plain document —
 * rather than nothing.
 *
 * Keys per entry:
 *   icon    full class attribute for the glyph, as DistributionLevel gives it
 *   hue     position on the hsl() ramp, to hand to `.ex-icon` as its `--h`
 *
 * There is deliberately no colour here: `.ex-icon` in mainOvermind.css turns
 * the hue into the ink and the tint, and it does it once for both themes, so
 * CSS stays authoritative the way ModalAccent leaves it authoritative. Draw a
 * format's glyph as
 *
 *     <span class="ex-icon" style="--h: <?= (int)$meta['hue'] ?>;">
 *         <i class="<?= h($meta['icon']) ?>"></i>
 *     </span>
 *
 * Adding a format: add it here, with the hue picked so neighbours in the list
 * do not collide — never reintroduce a per-view table.
 *
 * @see ExportFormatHelper for the view-side wrapper
 */

class ExportFormat
{
    /**
     * Keyed by the normalised format name (see normalise()).
     *
     * @var array
     */
    private static $formats = array(
        // ── MISP's own serialisations ──
        'json'            => array('icon' => 'file-code',      'hue' => 205),
        'xml'             => array('icon' => 'file-code',       'hue' => 265),
        'csv'             => array('icon' => 'file-csv',        'hue' => 145),
        'csvall'          => array('icon' => 'file-csv',        'hue' => 165),
        'csvwithcontext'  => array('icon' => 'file-csv',        'hue' => 165),
        'opendata'        => array('icon' => 'table-list',      'hue' => 130),

        // ── Detection rules ──
        'suricata'        => array('icon' => 'shield-halved',   'hue' => 15),
        'snort'           => array('icon' => 'shield-halved',   'hue' => 35),
        'bro'             => array('icon' => 'network-wired',   'hue' => 55),
        'yara'            => array('icon' => 'bug',             'hue' => 85),
        'yarajson'        => array('icon' => 'bug',             'hue' => 105),
        'openioc'         => array('icon' => 'file-shield',     'hue' => 250),

        // ── Structured threat intel ──
        'stix'            => array('icon' => 'share-nodes',     'hue' => 300),
        'stixjson'        => array('icon' => 'share-nodes',     'hue' => 310),
        'stix2'           => array('icon' => 'share-nodes',     'hue' => 320),

        // ── Network plumbing ──
        'rpz'             => array('icon' => 'globe',           'hue' => 190),
        'netfilter'       => array('icon' => 'filter',          'hue' => 175),
        'hosts'           => array('icon' => 'server',          'hue' => 200),

        // ── Flat lists and prose ──
        'text'            => array('icon' => 'file-lines',      'hue' => 225),
        'hashes'          => array('icon' => 'hashtag',         'hue' => 240),
        'context'         => array('icon' => 'layer-group',     'hue' => 285),
        'contextmarkdown' => array('icon' => 'file-lines',      'hue' => 295),
        'attack'          => array('icon' => 'table-cells',     'hue' => 5),
        'attacksightings' => array('icon' => 'table-cells',     'hue' => 350),
    );

    /**
     * Spellings that are the same format under another name. Applied after
     * normalise(), so both sides here are already normalised.
     *
     * @var array
     */
    private static $aliases = array(
        'stixxml'    => 'stix',
        'stix1'      => 'stix',
        'stix1xml'   => 'stix',
        'stix1json'  => 'stixjson',
        'stix2json'  => 'stix2',
        'csvsig'     => 'csv',
        'mispjson'   => 'json',
        'mispxml'    => 'xml',
    );

    /** A format the table does not know. */
    private static $fallback = array('icon' => 'file-arrow-down', 'hue' => 215);

    /**
     * @param string $format format key, in any of the spellings above
     * @return array array(icon, hue)
     */
    public static function get($format)
    {
        $key = self::normalise($format);
        if (isset(self::$aliases[$key])) {
            $key = self::$aliases[$key];
        }

        return self::expand(
            isset(self::$formats[$key]) ? self::$formats[$key] : self::$fallback
        );
    }

    /**
     * The whole table, keyed by its normalised name. For a caller handing it
     * to JavaScript rather than looking one format up.
     *
     * @return array
     */
    public static function all()
    {
        $out = array();
        foreach (self::$formats as $key => $meta) {
            $out[$key] = self::expand($meta);
        }

        return $out;
    }

    /**
     * @return array the entry an unknown format gets
     */
    public static function fallback()
    {
        return self::expand(self::$fallback);
    }

    /**
     * `Stix_XML` and `stix-xml` are the same key. Everything that is not a
     * letter or a digit goes, which is what makes the three surfaces' spellings
     * meet.
     *
     * @param string $format
     * @return string
     */
    private static function normalise($format)
    {
        return preg_replace('/[^a-z0-9]/', '', strtolower((string)$format));
    }

    /**
     * The table holds the glyph without its family prefix, the way the two
     * views that had it inlined did; callers get a full class attribute.
     *
     * @param array $meta
     * @return array
     */
    private static function expand(array $meta)
    {
        $meta['icon'] = 'fas fa-' . $meta['icon'];

        return $meta;
    }
}
