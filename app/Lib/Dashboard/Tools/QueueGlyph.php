<?php

/**
 * Inline-SVG glyph set for the QueueList render kind (DD-38).
 *
 * QueueList prefixes each background-queue row with a small per-queue
 * glyph so the queue identity is parsable at a glance (workers/jobs
 * chips carry the numbers + status colours). A widget names the glyph
 * per row via the row's `glyph` key (queue identifier from
 * BackgroundJobsTool::VALID_QUEUES); QueueList.ctp calls
 * QueueGlyph::get($name) to emit the markup.
 *
 * Inline SVG, not FontAwesome — same reason as StatGlyph (DD-32): the
 * dashboard layouts load different FA majors per theme (base/UiBeta
 * `font-awesome` = FA5/6, Overmind `fontawesome7.min` = FA7), so FA
 * class names render the wrong glyph (or nothing) depending on the
 * active theme. Inline SVG with `currentColor` is theme-independent.
 *
 * Glyphs are decorative (`aria-hidden`): the accessible name is the
 * queue name in the adjacent label.
 */
class QueueGlyph
{
    /**
     * Per-glyph inner SVG geometry, on a 0 0 24 24 viewBox. Stroke /
     * fill / linecaps come from the shared wrapper so each entry only
     * carries its shapes. Keys are the BackgroundJobsTool queue names.
     */
    const GLYPHS = array(
        // stack of boxes — `default` queue (generic worker workload)
        'default' =>
            '<rect x="3.5" y="13" width="7" height="7" rx="0.6"/>'
            . '<rect x="13.5" y="13" width="7" height="7" rx="0.6"/>'
            . '<rect x="8.5" y="3.5" width="7" height="7" rx="0.6"/>',
        // envelope — `email` queue
        'email' =>
            '<rect x="3" y="5.5" width="18" height="13" rx="1.5"/>'
            . '<path d="M3.5 6.5 L12 13 L20.5 6.5"/>',
        // lightning bolt — `cache` queue (fast/short-lived)
        'cache' =>
            '<path d="M13 3 L5 13.5 H11 L10 21 L19 9.5 H13 Z"/>',
        // flame — `prio` queue (high-priority, urgent). Asymmetric tip
        // (curls right) + a kink at the shoulder so it reads as fire
        // rather than a teardrop.
        'prio' =>
            '<path d="M13 3 C 13 6 16 7 16 11'
            . ' C 18 11 19 13 19 15 a7 7 0 0 1-14 0'
            . ' C 5 12 7 11 8 9 C 8 11 10 12 11 10 C 12 8 12 5 13 3 Z"/>'
            . '<path d="M12 14 c-1 1-2 2-2 3.5 a2.5 2.5 0 0 0 5 0'
            . ' c0-1.5-1.5-2-2-3.5 c0 1-0.5 1.5-1 0 Z"'
            . ' fill="currentColor" stroke="none"/>',
        // circular sync arrows — `update` queue (refresh)
        'update' =>
            '<path d="M20 7 a8 8 0 0 0-14-1"/>'
            . '<polyline points="20,3 20,7 16,7"/>'
            . '<path d="M4 17 a8 8 0 0 0 14 1"/>'
            . '<polyline points="4,21 4,17 8,17"/>',
        // clock — `scheduler` queue
        'scheduler' =>
            '<circle cx="12" cy="12" r="8.5"/>'
            . '<path d="M12 7 V12 L15.5 14"/>',
    );

    /**
     * Return the full inline-SVG markup for a named glyph, or '' for an
     * unknown / empty name (QueueList then renders the row without a
     * glyph slot icon).
     *
     * @param string|null $name
     * @return string
     */
    public static function get($name)
    {
        if (empty($name) || !isset(self::GLYPHS[$name])) {
            return '';
        }
        return '<svg class="misp-queue-glyph-svg" viewBox="0 0 24 24" fill="none"'
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
