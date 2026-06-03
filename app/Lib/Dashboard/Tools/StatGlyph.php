<?php

/**
 * Inline-SVG glyph set for the StatGrid render kind (DD-31/DD-32).
 *
 * StatGrid cards replace a per-metric text label with a small glyph
 * (the full field name moves to the card's `title` hover tooltip), so
 * the labels stop truncating in narrow cards. A widget names a glyph
 * per datum via the row's `icon` key (e.g. 'events', 'users', 'key');
 * StatGrid.ctp calls StatGlyph::get($name) to emit the markup.
 *
 * Why inline SVG and not FontAwesome: the dashboard layouts load
 * DIFFERENT FA majors per theme — the base/UiBeta layouts pull
 * `font-awesome` (FA5/6) while Overmind pulls `fontawesome7.min` — so
 * FA class names are not stable across themes and would render the
 * wrong icon (or nothing) depending on the active theme. Inline SVG
 * with `currentColor` is theme-independent, matching the dashboard
 * chrome and `empty_state.ctp`. The CSS layer colours the glyph from
 * the active theme's tokens.
 *
 * Glyphs are decorative (`aria-hidden`): the accessible name is the
 * field title carried on the card's `title` attribute.
 */
class StatGlyph
{
    /**
     * Per-glyph inner SVG geometry, on a 0 0 24 24 viewBox. Stroke /
     * fill / linecaps come from the shared wrapper so each entry only
     * carries its shapes.
     */
    const GLYPHS = array(
        // calendar — Events
        'calendar' =>
            '<rect x="3" y="4.5" width="18" height="16" rx="2"/>'
            . '<line x1="3" y1="9" x2="21" y2="9"/>'
            . '<line x1="8" y1="2.5" x2="8" y2="6"/>'
            . '<line x1="16" y1="2.5" x2="16" y2="6"/>',
        // tag — Attributes
        'tag' =>
            '<path d="M3.5 11.5 V4.5 a1 1 0 0 1 1-1 H11.5 L20.5 12.5'
            . ' a1 1 0 0 1 0 1.4 L13.9 20.5 a1 1 0 0 1-1.4 0 Z"/>'
            . '<circle cx="7.5" cy="7.5" r="1.3" fill="currentColor" stroke="none"/>',
        // stacked layers — Attributes / event (a derived ratio)
        'layers' =>
            '<path d="M12 3 L21 8 L12 13 L3 8 Z"/>'
            . '<path d="M3 12 L12 17 L21 12"/>'
            . '<path d="M3 16 L12 21 L21 16"/>',
        // chain link — Correlations
        'link' =>
            '<path d="M9 15 L15 9"/>'
            . '<path d="M10.5 6 L13 3.5 a4 4 0 0 1 6 6 L16.5 12"/>'
            . '<path d="M13.5 18 L11 20.5 a4 4 0 0 1-6-6 L7.5 12"/>',
        // pencil — Active proposals (suggested edits)
        'pencil' =>
            '<path d="M16.5 3.5 a2.1 2.1 0 0 1 3 3 L7 19 L3 20 L4 16 Z"/>'
            . '<line x1="14.5" y1="5.5" x2="17.5" y2="8.5"/>',
        // single person — Users
        'user' =>
            '<circle cx="12" cy="8" r="3.5"/>'
            . '<path d="M5 20 a7 7 0 0 1 14 0"/>',
        // key — Users with PGP keys
        'key' =>
            '<circle cx="8" cy="8" r="4"/>'
            . '<path d="M11 11 L20 20"/>'
            . '<line x1="17" y1="17" x2="19" y2="15"/>'
            . '<line x1="14.5" y1="14.5" x2="16.5" y2="12.5"/>',
        // office building — Organisations
        'building' =>
            '<rect x="5" y="3" width="14" height="18" rx="1"/>'
            . '<line x1="9" y1="7" x2="9" y2="9"/>'
            . '<line x1="15" y1="7" x2="15" y2="9"/>'
            . '<line x1="9" y1="12" x2="9" y2="14"/>'
            . '<line x1="15" y1="12" x2="15" y2="14"/>'
            . '<path d="M10 21 V17 H14 V21"/>',
        // house — Local organisations
        'home' =>
            '<path d="M4 11 L12 4 L20 11"/>'
            . '<path d="M6 9.5 V20 H18 V9.5"/>'
            . '<rect x="10" y="14" width="4" height="6"/>',
        // node tree — Event creator orgs
        'sitemap' =>
            '<rect x="9" y="3" width="6" height="5" rx="1"/>'
            . '<rect x="3" y="16" width="6" height="5" rx="1"/>'
            . '<rect x="15" y="16" width="6" height="5" rx="1"/>'
            . '<path d="M12 8 V12 M6 16 V12 H18 V16"/>',
        // two people — Average users / org
        'users' =>
            '<circle cx="9" cy="8" r="3"/>'
            . '<path d="M3 19 a6 6 0 0 1 12 0"/>'
            . '<path d="M16 6 a3 3 0 0 1 0 6"/>'
            . '<path d="M16.5 13 a6 6 0 0 1 4.5 6"/>',
        // speech bubble — Discussion threads
        'chat' =>
            '<path d="M4 5 H20 a1 1 0 0 1 1 1 V15 a1 1 0 0 1-1 1 H9'
            . ' L5 20 V16 H4 a1 1 0 0 1-1-1 V6 a1 1 0 0 1 1-1 Z"/>',
        // speech bubble with lines — Discussion posts
        'chat-lines' =>
            '<path d="M4 5 H20 a1 1 0 0 1 1 1 V15 a1 1 0 0 1-1 1 H9'
            . ' L5 20 V16 H4 a1 1 0 0 1-1-1 V6 a1 1 0 0 1 1-1 Z"/>'
            . '<line x1="7" y1="9" x2="17" y2="9"/>'
            . '<line x1="7" y1="12" x2="13" y2="12"/>',
        // shield with check — Advanced authkeys
        'shield' =>
            '<path d="M12 3 L20 6 V11 c0 5-3.5 8-8 10 c-4.5-2-8-5-8-10 V6 Z"/>'
            . '<path d="M9 12 L11 14 L15 9"/>',
    );

    /**
     * Return the full inline-SVG markup for a named glyph, or '' for an
     * unknown / empty name (StatGrid then falls back to the text label).
     *
     * @param string|null $name
     * @return string
     */
    public static function get($name)
    {
        if (empty($name) || !isset(self::GLYPHS[$name])) {
            return '';
        }
        return '<svg class="misp-stat-glyph-svg" viewBox="0 0 24 24" fill="none"'
            . ' stroke="currentColor" stroke-width="1.6" stroke-linecap="round"'
            . ' stroke-linejoin="round" aria-hidden="true" focusable="false">'
            . self::GLYPHS[$name]
            . '</svg>';
    }

    /**
     * Whether a glyph name resolves to markup.
     *
     * @param string|null $name
     * @return bool
     */
    public static function has($name)
    {
        return !empty($name) && isset(self::GLYPHS[$name]);
    }
}
