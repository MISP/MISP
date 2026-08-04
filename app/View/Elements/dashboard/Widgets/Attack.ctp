<?php
/**
 * Attack renderer (dashboard v2) — ATT&CK heatmap, REDESIGNED (AD-15, 2026-06-02).
 *
 * Static MITRE ATT&CK heatmap for widgets that declare `$render = 'Attack'`
 * (AttackWidget). The handler returns the full Event::restSearch 'attack'
 * export shape:
 *
 *   $data = [
 *     'tabs'          => [ <tabName> => [ <colName> => [ {cell}, ... ], ... ], ... ],
 *     'columnOrders'  => [ <tabName> => [ colName, colName, ... ], ... ],
 *     'scores'        => [ <tag_name> => int, ... ],   // distinct-event count
 *     'maxScore'      => int,                          // max per-cluster (unused here)
 *     'defaultTabName'=> '<tabName>',
 *     'removeTrailing'=> int,    // strip N space-separated chunks from the value end
 *     ... (other keys ignored)
 *   ];
 *
 * Each `{cell}` carries `value`, `tag_name` (the scores lookup key), and
 * **`external_id`** — the authoritative T-ID stamped by Galaxy::getMatrix
 * (`T1566` = technique, `T1566.001` = sub-technique).
 *
 * REDESIGN (AD-15) — supersedes the prior thin-bar density map:
 *  1. HIDE INACTIVE — only technique groups with a non-zero aggregate render;
 *     tactic columns with no active group are dropped entirely.
 *  2. LABELED CELLS — each cell shows the technique name + T-ID + count,
 *     readable without hover (wall-display usable).
 *  3. TECHNIQUE / SUB-TECHNIQUE AGGREGATION — sub-techniques roll up into their
 *     parent technique (grouped per tactic column by parent T-ID off
 *     `external_id`). The parent cell shows the SUM of its own + its
 *     sub-techniques' event-counts; clicking it unfolds the sub-techniques on
 *     demand (native <details>/<summary> — no JS, multi-widget-safe).
 *  4. SINGLE RED RAMP + LEGEND — the export's multi-hue colours are ignored;
 *     each cell is shaded in-renderer on a single-hue red ramp, √-scaled and
 *     normalised to the global max aggregate (the hit distribution is heavily
 *     skewed, so a linear ramp would wash out the mid-range). A small legend
 *     keys the shading; its gradient stops are sampled from the same ramp.
 *
 * Data layer (AttackExport / Galaxy::getMatrix) is untouched — everything here
 * works off the `tabs` + `scores` payload already delivered.
 *
 * Token-driven CSS lives in dashboard.default.css / dashboard.midnight.css
 * under "Attack renderer". Cell backgrounds are full-opacity computed reds
 * (theme-independent); the text colour is luminance-picked per cell so labels
 * stay legible on either theme.
 */
if (!is_array($data) || empty($data)) {
    echo '<div class="misp-list-empty">' . __('No filter configured. Set the `time_window` / `filters` config to populate the heatmap.') . '</div>';
    return;
}

$tabs           = isset($data['tabs'])           ? (array)$data['tabs']           : array();
$columnOrders   = isset($data['columnOrders'])   ? (array)$data['columnOrders']   : array();
$scores         = isset($data['scores'])         ? (array)$data['scores']         : array();
$defaultTab     = isset($data['defaultTabName']) ? (string)$data['defaultTabName'] : '';

if (empty($tabs) || $defaultTab === '' || empty($tabs[$defaultTab])) {
    echo '<div class="misp-list-empty">' . __('No matrix data returned.') . '</div>';
    return;
}

$tabCols = $tabs[$defaultTab];
$colOrder = isset($columnOrders[$defaultTab]) && is_array($columnOrders[$defaultTab])
    ? $columnOrders[$defaultTab]
    : array_keys($tabCols);

/**
 * Derive a clean technique label. We hold the authoritative T-ID
 * (`external_id`), and matrix cell values are formatted "Name - <id>", so
 * strip a trailing " - <external_id>" suffix (exact; works for techniques,
 * sub-techniques, and legacy non-T clusters alike). If the value doesn't end
 * with its id (e.g. external_id missing), return it unchanged rather than
 * risk chopping real words.
 */
$cellLabel = function ($value, $ext) {
    $value = (string)$value;
    if ($ext !== '' && $value !== '' && strlen($value) >= strlen($ext)
        && substr($value, -strlen($ext)) === $ext) {
        $label = rtrim(rtrim(substr($value, 0, -strlen($ext))), " -");
        if ($label !== '') {
            return $label;
        }
    }
    return $value;
};

/** "defense-evasion" → "Defense Evasion". */
$formatTactic = function ($key) {
    return ucwords(str_replace('-', ' ', (string)$key));
};

/**
 * Single-hue red ramp. $t in [0,1] → [#rrggbb background, #rrggbb text].
 * HSL(h=0, s=72%, L 88%→30%); text flips dark/white by lightness so labels
 * stay legible regardless of the dashboard theme (cells are opaque).
 */
$ramp = function ($t) {
    $t = max(0.0, min(1.0, (float)$t));
    $s = 0.72;
    $l = 0.88 - $t * (0.88 - 0.30);
    $c = (1 - abs(2 * $l - 1)) * $s;   // h=0 ⇒ only the R' channel is non-zero
    $m = $l - $c / 2;
    $r = (int)round(($c + $m) * 255);
    $g = (int)round($m * 255);
    $b = (int)round($m * 255);
    $bg = sprintf('#%02x%02x%02x', $r, $g, $b);
    $text = $l > 0.58 ? '#5a1111' : '#ffffff';
    return array($bg, $text);
};

/** Perceptual (√) intensity for a raw score against the global max aggregate. */
$intensity = function ($score, $max) {
    if ($max <= 0 || $score <= 0) {
        return 0.0;
    }
    return sqrt(min(1.0, $score / $max));
};

// ── Pass 0: global parent-technique name map (resolves orphan sub-techniques
//    whose parent cell isn't in the same tactic column — ~7/195 on the dev corpus).
$parentNames = array();
foreach ($colOrder as $colKey) {
    if (!isset($tabCols[$colKey]) || !is_array($tabCols[$colKey])) {
        continue;
    }
    foreach ($tabCols[$colKey] as $cell) {
        if (!is_array($cell)) {
            continue;
        }
        $ext = isset($cell['external_id']) ? (string)$cell['external_id'] : '';
        if (preg_match('/^T\d+$/', $ext)) {
            $parentNames[$ext] = $cellLabel($cell['value'] ?? '', $ext);
        }
    }
}

// ── Pass 1: build active groups per column (aggregate, hide inactive) + global max.
$renderCols = array();
$maxAgg = 0;
foreach ($colOrder as $colKey) {
    if (!isset($tabCols[$colKey]) || !is_array($tabCols[$colKey])) {
        continue;
    }
    $groups = array();   // parentTid => ['own'=>int, 'ownLabel'=>?string, 'subs'=>[]]
    foreach ($tabCols[$colKey] as $cell) {
        if (!is_array($cell)) {
            continue;
        }
        $ext   = isset($cell['external_id']) ? (string)$cell['external_id'] : '';
        $tag   = isset($cell['tag_name']) ? (string)$cell['tag_name'] : '';
        $score = ($tag !== '' && isset($scores[$tag])) ? (int)$scores[$tag] : 0;
        $label = $cellLabel($cell['value'] ?? '', $ext);

        if (preg_match('/^(T\d+)\.\d+$/', $ext, $m)) {
            // sub-technique → roll up under its parent T-ID
            $pt = $m[1];
            if (!isset($groups[$pt])) {
                $groups[$pt] = array('own' => 0, 'ownLabel' => null, 'subs' => array());
            }
            $groups[$pt]['subs'][] = array('label' => $label, 'tid' => $ext, 'score' => $score);
        } elseif (preg_match('/^T\d+$/', $ext)) {
            // parent technique cell
            if (!isset($groups[$ext])) {
                $groups[$ext] = array('own' => 0, 'ownLabel' => null, 'subs' => array());
            }
            $groups[$ext]['own'] = $score;
            $groups[$ext]['ownLabel'] = $label;
        } else {
            // non-T external_id (legacy / pre-attack) → standalone leaf group
            $key = $ext !== '' ? $ext : ('_' . $label);
            if (!isset($groups[$key])) {
                $groups[$key] = array('own' => 0, 'ownLabel' => null, 'subs' => array());
            }
            $groups[$key]['own'] = $score;
            $groups[$key]['ownLabel'] = $label;
        }
    }

    $active = array();
    foreach ($groups as $pt => $g) {
        $own = isset($g['own']) ? (int)$g['own'] : 0;
        $subs = isset($g['subs']) ? $g['subs'] : array();
        $agg = $own;
        foreach ($subs as $s) {
            $agg += (int)$s['score'];
        }
        if ($agg <= 0) {
            continue;   // hide inactive technique group
        }
        if (!empty($g['ownLabel'])) {
            $label = $g['ownLabel'];
        } elseif (isset($parentNames[$pt])) {
            $label = $parentNames[$pt];
        } else {
            $label = $pt;   // orphan fallback: the parent T-ID itself
        }
        $asubs = array();
        foreach ($subs as $s) {
            if ((int)$s['score'] > 0) {
                $asubs[] = $s;
            }
        }
        usort($asubs, function ($a, $b) {
            return (int)$b['score'] <=> (int)$a['score'];
        });
        $active[] = array('tid' => $pt, 'label' => $label, 'agg' => $agg, 'subs' => $asubs);
        if ($agg > $maxAgg) {
            $maxAgg = $agg;
        }
    }
    if (empty($active)) {
        continue;   // hide tactic column with no active group
    }
    usort($active, function ($a, $b) {
        return (int)$b['agg'] <=> (int)$a['agg'];
    });
    $renderCols[$colKey] = $active;
}

if (empty($renderCols) || $maxAgg <= 0) {
    echo '<div class="misp-list-empty">' . __('No active ATT&CK techniques in the selected window.') . '</div>';
    return;
}

// ── Render a single labeled cell (parent summary or sub). $extraClass is appended.
$renderCell = function ($label, $tid, $score, $extraClass) use ($ramp, $intensity, $maxAgg) {
    list($bg, $tx) = $ramp($intensity($score, $maxAgg));
    $title = $label . ' · ' . $tid . ' · ' . $score . ' ' . __('event(s)');
    $style = 'background-color:' . $bg . ';color:' . $tx;
    return '<span class="misp-attack-cell ' . h($extraClass) . '" style="' . $style . '" title="' . h($title) . '">'
        . '<span class="misp-attack-cell-name">' . h($label) . '</span>'
        . '<span class="misp-attack-cell-meta"><span class="misp-attack-cell-tid">' . h($tid) . '</span>'
        . '<span class="misp-attack-cell-count">' . (int)$score . '</span></span>'
        . '</span>';
};

// ── Legend gradient: sample the exact ramp at 5 stops (faithful key, √-scaled).
$legendStops = array();
for ($k = 0; $k <= 4; $k++) {
    $s = ($k / 4) * $maxAgg;
    list($bg) = $ramp($intensity($s, $maxAgg));
    $legendStops[] = $bg;
}
$legendGradient = 'linear-gradient(to right,' . implode(',', $legendStops) . ')';

echo '<div class="misp-attack">';

// legend
echo '<div class="misp-attack-legend">';
echo '<span class="misp-attack-legend-cap">' . __('Events / technique') . '</span>';
echo '<span class="misp-attack-legend-min">0</span>';
echo '<span class="misp-attack-legend-bar" style="background:' . $legendGradient . '" title="' . h(__('Shading uses a square-root scale, normalised to the busiest technique.')) . '"></span>';
echo '<span class="misp-attack-legend-max">' . (int)$maxAgg . '</span>';
echo '</div>';

echo '<div class="misp-attack-scroll">';
echo '<div class="misp-attack-grid">';
foreach ($renderCols as $colKey => $groups) {
    echo '<div class="misp-attack-col">';
    echo '<div class="misp-attack-col-header">';
    echo '<span class="misp-attack-col-name" title="' . h($colKey) . '">' . h($formatTactic($colKey)) . '</span>';
    echo '<span class="misp-attack-col-count">' . count($groups) . '</span>';
    echo '</div>';

    echo '<div class="misp-attack-col-cells">';
    foreach ($groups as $g) {
        if (!empty($g['subs'])) {
            // parent with active sub-techniques → unfoldable <details>
            echo '<details class="misp-attack-group">';
            echo '<summary>' . $renderCell($g['label'], $g['tid'], $g['agg'], 'misp-attack-cell--parent') . '</summary>';
            echo '<div class="misp-attack-subs">';
            foreach ($g['subs'] as $s) {
                echo $renderCell($s['label'], $s['tid'], (int)$s['score'], 'misp-attack-cell--sub');
            }
            echo '</div>';
            echo '</details>';
        } else {
            // leaf technique (no active sub-techniques)
            echo $renderCell($g['label'], $g['tid'], $g['agg'], 'misp-attack-cell--leaf');
        }
    }
    echo '</div>';
    echo '</div>';
}
echo '</div>';
echo '</div>';
echo '</div>';
