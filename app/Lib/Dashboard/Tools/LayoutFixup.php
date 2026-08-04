<?php

/**
 * Per-widget on-read fix-ups for the dashboard v2 layout shape (DD-05).
 *
 * The `UserSetting:dashboard` row stays as a bare array of widget
 * dictionaries — no `{scope, widgets}` envelope (DD-05 retracted the
 * Q1 envelope plan). The only shape evolution v2 introduces is
 * per-widget:
 *
 *   - `width` / `height` (v1) → `w` / `h` (v2 — what the GridModule
 *     stores in `data-position-{w,h}` for Pragmatic DnD's grid math).
 *   - mint a stable `instance_id` if missing, so toolbar bulk-edits
 *     and configure saves can address widgets independently.
 *
 * Idempotent: feeding a v2-shape array through is a no-op. Fix-ups
 * apply on read (so legacy rows render correctly) AND on write (so
 * the persisted shape is canonical and a future read needs no
 * re-fixing).
 */
class LayoutFixup
{
    /**
     * Apply v1 → v2 per-widget fix-ups. Top-level stays a bare array.
     *
     * @param array $widgets
     * @return array
     */
    public static function applyReadFixups($widgets)
    {
        if (!is_array($widgets)) {
            return array();
        }
        $out = array();
        foreach (array_values($widgets) as $k => $w) {
            if (!is_array($w)) {
                continue;
            }
            // v1 nests x/y/width/height in a `position` sub-array; v2
            // keeps the nesting but renames width→w / height→h so the
            // GridModule's grid-math keys line up. Preserve the numeric
            // values exactly; drop the old keys so the persisted shape
            // is clean.
            if (isset($w['position']) && is_array($w['position'])) {
                $p = $w['position'];
                if (array_key_exists('width', $p)) {
                    if (!array_key_exists('w', $p)) {
                        $p['w'] = $p['width'];
                    }
                    unset($p['width']);
                }
                if (array_key_exists('height', $p)) {
                    if (!array_key_exists('h', $p)) {
                        $p['h'] = $p['height'];
                    }
                    unset($p['height']);
                }
                $w['position'] = $p;
            }
            // Mint instance_id when missing. Position-based so the
            // mint is deterministic for the same input on a single
            // read — Phase 5.5 acceptance criterion.
            if (empty($w['instance_id'])) {
                $w['instance_id'] = sprintf('w_%d', $k + 1);
            }
            $out[] = $w;
        }
        return $out;
    }
}
