<?php

/**
 * Server-side SVG miniature renderer for dashboard templates
 * (PRD §5.4 F4.2, Phase 4 tasks 2 + 3).
 *
 * Composes a small SVG showing each saved widget as a positioned
 * rect with a short label (the widget's $title minus surrounding
 * decoration, truncated to fit). On-demand: rendered at gallery-
 * render time from the template's bare widget array — no disk
 * cache, no headless browser, no per-template invalidation.
 * Always current with the saved layout. The Phase 4 task 3
 * "Refresh-thumbnail" line is closed as a no-op alongside this
 * file because a cache-less renderer has nothing to refresh.
 *
 * Output shape: a single inline <svg> with viewBox="0 0 80 45"
 * (matches `.misp-gallery-card-thumbnail`'s 16:9 slot) using
 * `currentColor` for all strokes/fills so the miniature inherits
 * the active theme's gallery-card text colour.
 *
 * Layout math:
 *   - Compute bounding box: maxX = max(x+w), maxY = max(y+h).
 *   - Normalise the column count to ≥12 (gridstack default) so a
 *     single-column layout doesn't get stretched edge-to-edge in
 *     the miniature, and the row count to ≥6 so a single-row
 *     layout doesn't fill the viewBox vertically.
 *   - Independent scaleX = 80/cols, scaleY = 45/rows. The aspect
 *     of each rect doesn't match the on-board aspect exactly —
 *     the miniature trades cell-aspect fidelity for filling the
 *     viewBox cleanly. The arrangement (which widget is where) is
 *     what the user reads at a glance.
 *
 * Label sizing: font-size 3 (≈1.6 SVG units per character at the
 * thin stroke). The truncation heuristic computes max chars from
 * the rect width and ellipsises on overflow; sub-3-char rects
 * render bare. Tiny rects (height < 5) also render bare.
 *
 * Empty input falls back to the original 5-rect placeholder shape
 * so the gallery's visual rhythm is preserved for empty templates.
 */
class TemplatePreview
{
    /**
     * Render the SVG miniature.
     *
     * @param array $widgets Bare widget array (DD-01 shape — each
     *   item carries `widget`, `position` { x, y, w, h }; legacy
     *   `width`/`height` keys also accepted).
     * @param array $titleMap [className => human-readable title]
     *   (typically from Dashboard::loadAllWidgets). Optional —
     *   missing entries fall back to a CamelCase-spaced
     *   transformation of the class name with `Widget` stripped.
     * @return string Inline <svg> markup.
     */
    public static function render(array $widgets, array $titleMap = array())
    {
        $valid = array();
        foreach ($widgets as $w) {
            $rect = self::positionRect($w);
            if ($rect === null) {
                continue;
            }
            $valid[] = array('rect' => $rect, 'widget' => $w);
        }
        if (empty($valid)) {
            return self::renderEmpty();
        }

        $maxX = 0;
        $maxY = 0;
        foreach ($valid as $entry) {
            list($x, $y, $w, $h) = $entry['rect'];
            if ($x + $w > $maxX) $maxX = $x + $w;
            if ($y + $h > $maxY) $maxY = $y + $h;
        }
        // Floor to gridstack's default 12 columns + 6 rows so a
        // sparse layout doesn't fill the viewBox edge to edge.
        $cols = max($maxX, 12);
        $rows = max($maxY, 6);
        $scaleX = 80.0 / $cols;
        $scaleY = 45.0 / $rows;
        $gap = 0.6;

        $inner = '';
        foreach ($valid as $entry) {
            list($x, $y, $w, $h) = $entry['rect'];
            $rx = $x * $scaleX + $gap;
            $ry = $y * $scaleY + $gap;
            $rw = max(0, $w * $scaleX - 2 * $gap);
            $rh = max(0, $h * $scaleY - 2 * $gap);

            $inner .= sprintf(
                '<rect x="%.2f" y="%.2f" width="%.2f" height="%.2f" rx="0.8"/>',
                $rx, $ry, $rw, $rh
            );

            $className = isset($entry['widget']['widget']) ? $entry['widget']['widget'] : '';
            $title = isset($titleMap[$className])
                ? $titleMap[$className]
                : self::titleFromClassName($className);
            $label = self::truncateLabel($title, $rw);
            if ($label !== '' && $rh >= 5.0) {
                $cx = $rx + $rw / 2;
                $cy = $ry + $rh / 2 + 1.0;
                $inner .= sprintf(
                    '<text x="%.2f" y="%.2f" text-anchor="middle" '
                    . 'font-size="3" fill="currentColor" stroke="none">%s</text>',
                    $cx,
                    $cy,
                    htmlspecialchars($label, ENT_QUOTES | ENT_HTML5, 'UTF-8')
                );
            }
        }
        return self::wrap($inner);
    }

    /**
     * Extract { x, y, w, h } as ints from a widget's position dict.
     * Accepts both v2 (`w`/`h`) and legacy v1 (`width`/`height`)
     * key shapes. Returns null when the position is missing or any
     * dimension is non-positive (defensive — keeps a malformed row
     * from blowing up the gallery render).
     *
     * @param array $widget
     * @return array|null [x, y, w, h]
     */
    private static function positionRect($widget)
    {
        if (!isset($widget['position']) || !is_array($widget['position'])) {
            return null;
        }
        $p = $widget['position'];
        $x = isset($p['x']) ? (int)$p['x'] : 0;
        $y = isset($p['y']) ? (int)$p['y'] : 0;
        $w = isset($p['w']) ? (int)$p['w'] : (isset($p['width']) ? (int)$p['width'] : 0);
        $h = isset($p['h']) ? (int)$p['h'] : (isset($p['height']) ? (int)$p['height'] : 0);
        if ($w <= 0 || $h <= 0) {
            return null;
        }
        if ($x < 0) $x = 0;
        if ($y < 0) $y = 0;
        return array($x, $y, $w, $h);
    }

    /**
     * Empty-state miniature — keeps the gallery card visually
     * weighted when a template has no widgets (rare; usually a
     * site-admin scaffolding row).
     *
     * @return string
     */
    private static function renderEmpty()
    {
        return self::wrap(
            '<rect x="6" y="6" width="30" height="14" rx="2"/>'
            . '<rect x="40" y="6" width="34" height="14" rx="2"/>'
            . '<rect x="6" y="24" width="20" height="15" rx="2"/>'
            . '<rect x="30" y="24" width="20" height="15" rx="2"/>'
            . '<rect x="54" y="24" width="20" height="15" rx="2"/>'
        );
    }

    /**
     * Wrap the inner SVG geometry in the common envelope. Width /
     * height are 100% so the CSS layer drives the rendered size;
     * stroke="currentColor" lets the miniature inherit theme
     * colours.
     *
     * @param string $inner
     * @return string
     */
    private static function wrap($inner)
    {
        return '<svg viewBox="0 0 80 45" preserveAspectRatio="xMidYMid meet" '
            . 'width="100%" height="100%" fill="none" '
            . 'stroke="currentColor" stroke-width="1" '
            . 'stroke-linecap="round" stroke-linejoin="round">'
            . $inner
            . '</svg>';
    }

    /**
     * Fallback label when no $title is available in the title map —
     * strips a trailing "Widget" suffix and inserts spaces at
     * CamelCase boundaries (and at acronym-then-titlecase
     * boundaries — so "APIActivity" → "API Activity", not
     * "A P I Activity"). Returns the class name unchanged on
     * regex failure; empty input returns empty.
     *
     * @param string $className
     * @return string
     */
    public static function titleFromClassName($className)
    {
        if ($className === '' || $className === null) return '';
        $name = preg_replace('/Widget$/', '', $className);
        $name = preg_replace(
            '/(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])/',
            ' ',
            $name
        );
        return $name;
    }

    /**
     * Truncate a label to fit a given rect width. Heuristic: at
     * font-size 3 each character is roughly 1.6 SVG units wide
     * with a thin sans-serif fallback. Sub-3-char rects get
     * blanked (the ellipsis alone reads as noise).
     *
     * @param string $label
     * @param float $rectWidth
     * @return string
     */
    private static function truncateLabel($label, $rectWidth)
    {
        $maxChars = (int)floor(($rectWidth - 1.0) / 1.6);
        if ($maxChars < 3) return '';
        if (mb_strlen($label) <= $maxChars) return $label;
        return rtrim(mb_substr($label, 0, $maxChars - 1)) . '…';
    }
}
