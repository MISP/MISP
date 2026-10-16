<?php
/**
 * Where the bands sit.
 *
 * A reader who disagrees with a signal-strength band needs the cut-off before
 * the disagreement is about anything, and the conditions strip already
 * links to the profile that holds it. This is the number that link
 * would take them to.
 *
 * **`min_signals` is on the tile because it is the surprise.** A value
 * scoring 80 still bands `medium` if only two signals added points —
 * signal strength is high when several independent readings agree, not
 * when one is generous (`ValueVerdictTool::signalStrengthBand()`). That
 * is the one rule here a reader cannot infer from a band they are
 * looking at, and
 * leaving it off would make the tile's two numbers a promise the
 * engine does not keep.
 *
 * **The high cut-off takes the value slot.** It is the threshold that
 * decides whether a record is worth acting on; `medium` is the floor
 * under it and belongs in the qualifying line.
 *
 * **The scale is drawn because this is the one tile whose value is a
 * position rather than a quantity.** *60* means nothing without the
 * 0–100 it sits on, and the three segments are the three bands at
 * their real widths — a profile that moved `high` to 80 draws a
 * visibly narrower one. It carries **no hue**: signal strength is a magnitude
 * and `value-palette.css` reserves colour for the lean, so the bands
 * separate by ink weight, which is the same *carries* against *lacks*
 * pairing the worklist's signal-strength bar already uses.
 *
 * Free: the thresholds come from the profile phase 7 already resolved.
 * Where a profile declares none, the figures shown are the engine's
 * own fallbacks rather than a blank, because those are the numbers it
 * would actually band with.
 *
 * @var array{high: int, medium: int, min_signals: int} $bands
 */
$high = (int)$bands['high'];
$medium = (int)$bands['medium'];
/*
 * The widths are the bands' own, clamped so a profile with the
 * thresholds crossed over — `high` below `medium`, which the engine
 * resolves by testing `high` first — draws a flat scale rather than a
 * negative segment.
 */
$lowWidth = max(0, min(100, $medium));
$mediumWidth = max(0, min(100 - $lowWidth, $high - $medium));
$highWidth = max(0, 100 - $lowWidth - $mediumWidth);
?>
<div class="vi-tile" data-vi-tile="bands">
    <div class="vi-tile__label"><i class="fas fa-gauge-high vi-tile__icon" aria-hidden="true"></i><?= h(__('Signal-strength bands')) ?></div>
    <div class="vi-tile__figure">
        <div class="vi-tile__value">
            <?= h(number_format($bands['high'])) ?>
        </div>
        <div class="vi-bandbar" aria-hidden="true" data-vi-bandbar>
            <i class="vi-bandbar__seg vi-bandbar__seg--low"
               style="flex-grow: <?= h($lowWidth) ?>"></i>
            <i class="vi-bandbar__seg vi-bandbar__seg--medium"
               style="flex-grow: <?= h($mediumWidth) ?>"></i>
            <i class="vi-bandbar__seg vi-bandbar__seg--high"
               style="flex-grow: <?= h($highWidth) ?>"></i>
        </div>
    </div>
    <div class="vi-tile__sub"><?= sprintf(
        h(__(
            'and above is rated high, %s and above medium. High also'
            . ' needs %s to agree.'
        )),
        '<b>' . h(number_format($bands['medium'])) . '</b>',
        '<b>' . h(number_format($bands['min_signals'])) . '</b> ' . h(__n(
            'signal',
            'signals',
            $bands['min_signals']
        ))
    ) ?></div>
</div>
