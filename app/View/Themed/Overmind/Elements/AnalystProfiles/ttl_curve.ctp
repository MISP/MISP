<?php
/**
 * The lifetime the numbers beside it describe, drawn.
 *
 * MISP's polynomial at the profile's own decay speed —
 * `1 − (elapsed / ttl)^(1 / speed)` — over the shortest bucket, with
 * the aging mark where the fraction says it falls and, when a value is
 * on the bench, where that value sits on the line.
 *
 * Inline SVG and no client JS: the curve is a function of four numbers
 * the server already has, and a chart library loaded to draw one
 * polyline is a chart library loaded for nothing.
 *
 * **It redraws on every edit all the same.** The figure sits in the
 * relevance section and the editor's recompute only ever swapped the
 * bench, so moving the decay speed changed the numbers under it and
 * left the line it is a picture of exactly where it was — the one
 * control on this page whose whole point is the shape it makes. The
 * recompute now carries this element back with the bench and the editor
 * swaps both (`analyst-profile.js`), which keeps the arithmetic here,
 * on the server, rather than growing a second copy of the polynomial in
 * JavaScript to animate it with.
 *
 * **It draws three bands, because the axis has three states.** The
 * first version marked day 60 `aging` and ended the plot at the
 * lifetime with a bare `90` on the tick — so the only labelled
 * threshold was the first one, and `aging` read as the end of the line
 * rather than as the middle of three. It is asked, and the answer was
 * not on the figure. The x-axis runs past the lifetime now, the curve
 * stays flat on zero out there, and `current` / `aging` / `expired` are
 * each named under the stretch they own.
 *
 * @var array $block The `ttl_buckets` map, a row per bucket
 * @var array $section
 * @var array|null $runway The bench value's relevance, when there is one
 */
App::uses('ValueRelevanceTool', 'Tools/ValueIntelligence');
$numbers = array();
foreach ($block['entries'] as $entry) {
    if (empty($entry['key_field'])) {
        continue;
    }
    $field = $entry['key_field'];
    $numbers[$field['key']] = $field['value'] === null
        ? $field['default']
        : $field['value'];
}
$ttl = isset($numbers['short']) ? (int)$numbers['short'] : 90;
if ($ttl <= 0) {
    $ttl = 90;
}

$speed = 1.0;
$aging = 0.33;
foreach ($section['blocks'] as $candidate) {
    if ($candidate['kind'] !== 'fields' || $candidate['id'] !== 'clock') {
        continue;
    }
    foreach ($candidate['fields'] as $field) {
        $value = $field['value'] === null ? $field['default'] : $field['value'];
        if ($field['key'] === 'decay_speed' && $value > 0) {
            $speed = (float)$value;
        }
        if ($field['key'] === 'aging_fraction') {
            $aging = (float)$value;
        }
    }
}

$left = 30;
$right = 250;
$top = 12;
$bottom = 96;
/*
 * How far past the lifetime the axis runs. `expired` begins *at* the
 * lifetime, so an axis that stops there has nowhere to put the word —
 * which is how the figure came to show two states and name one.
 */
$span = 1.25;
$at = function ($fractionElapsed) use ($left, $right, $span) {
    return round($left + ($right - $left) * ($fractionElapsed / $span), 2);
};
$height = function ($runway) use ($top, $bottom) {
    return round($bottom - ($bottom - $top) * $runway, 2);
};

/*
 * Twelve samples is enough for a line and more than enough for a
 * curve: at speed 1 it is straight and the extra points cost nothing,
 * away from 1 the bow is smooth. The thirteenth point is the flat run
 * past the lifetime, which is not a sample of the polynomial — it is
 * the statement that nothing comes back.
 */
$points = array();
for ($i = 0; $i <= 12; $i++) {
    $elapsed = $i / 12;
    /*
     * Not `$runway`: that name holds the value on the bench, and the
     * first version of this loop overwrote it with its last sample —
     * so the curve drew itself correctly and then lost the point
     * saying where this value sits on it.
     */
    $remaining = ValueRelevanceTool::runway($elapsed, 1, $speed);
    $points[] = $at($elapsed) . ',' . $height($remaining);
}
$points[] = $at($span) . ',' . $height(0);

/*
 * Where aging begins: the elapsed fraction at which the runway falls
 * to the aging fraction, which is the curve read backwards.
 */
$agingElapsed = ValueRelevanceTool::agingElapsed($aging, $speed);
$agingDay = ValueRelevanceTool::agingDay($aging, $speed, $ttl);

$agingX = $at($agingElapsed);
$ttlX = $at(1);
/*
 * A band too narrow for its own word goes unlabelled rather than
 * printing one over its neighbour: an aging fraction near 0 or 1
 * squeezes one of the three to nothing, and the two that are legible
 * still carry the reading.
 */
$bands = array();
foreach (array(
    array('current', $left, $agingX, __('current')),
    array('aging', $agingX, $ttlX, __('aging')),
    array('expired', $ttlX, $right, __('expired')),
) as $band) {
    list($id, $from, $to, $word) = $band;
    $bands[] = array(
        'id' => $id,
        'from' => $from,
        'to' => $to,
        'word' => $word,
        'mid' => round(($from + $to) / 2, 2),
        'room' => ($to - $from) >= 4.2 * mb_strlen($word),
    );
}

$here = null;
if (!empty($runway) && isset($runway['runway'])
    && isset($runway['elapsed_days']) && isset($runway['ttl']['days'])
    && $runway['ttl']['days'] > 0
) {
    $here = array(
        'elapsed' => min($span, $runway['elapsed_days'] / $runway['ttl']['days']),
        'runway' => max(0, min(1, $runway['runway'])),
        'days' => (int)$runway['elapsed_days'],
        'pct' => (int)round($runway['runway'] * 100),
    );
}

$label = sprintf(
    __('Relevance falls from 100%% at day zero to nothing at day %1$s.'
        . ' It counts as current until day %2$s, as aging from there to'
        . ' day %1$s, and as expired after that.'),
    $ttl,
    $agingDay
);
if ($here !== null) {
    $label .= ' ' . sprintf(
        __('This value sits at day %1$s with %2$s%% of its runway left.'),
        $here['days'],
        $here['pct']
    );
}
?>
<figure class="ttl-curve">
    <figcaption>
        <b><?= h(sprintf(
            __n('%1$s day at decay speed %2$s',
                '%1$s days at decay speed %2$s', $ttl),
            $ttl,
            $speed
        )) ?></b>
        <span class="wb-sub"><?= h(sprintf(
            __('the %s bucket'), 'short'
        )) ?></span>
    </figcaption>
    <svg viewBox="0 0 260 118" role="img" aria-label="<?= h($label) ?>">
        <?php foreach ($bands as $band): ?>
            <rect class="ttl-band ttl-band-<?= h($band['id']) ?>"
                  x="<?= $band['from'] ?>" y="8"
                  width="<?= round($band['to'] - $band['from'], 2) ?>"
                  height="<?= $bottom - 8 ?>" />
        <?php endforeach; ?>
        <polyline class="ttl-ax"
                  points="<?= $left ?>,8 <?= $left ?>,<?= $bottom ?> <?= $right ?>,<?= $bottom ?>" />
        <polyline class="ttl-line" points="<?= h(implode(' ', $points)) ?>" />
        <line class="ttl-aging" x1="<?= $agingX ?>" y1="8"
              x2="<?= $agingX ?>" y2="<?= $bottom ?>" />
        <line class="ttl-aging" x1="<?= $ttlX ?>" y1="8"
              x2="<?= $ttlX ?>" y2="<?= $bottom ?>" />
        <?php foreach ($bands as $band): ?>
            <?php if (!$band['room']) { continue; } ?>
            <text class="ttl-t ttl-band-t" x="<?= $band['mid'] ?>" y="106"
                  text-anchor="middle"><?= h($band['word']) ?></text>
        <?php endforeach; ?>
        <?php
        /*
         * Both thresholds carry their day. The lifetime's is the one
         * the old figure left as a bare axis tick, which is what let
         * `aging` be read as the end of the line.
         */
        ?>
        <?php
        /*
         * Anchored to the left of their own line rather than centred on
         * it: a dashed rule drawn through the middle of `day 60` is the
         * label and the thing it labels fighting for the same pixels.
         *
         * Dropped entirely when that leaves it nowhere to sit — an
         * aging fraction near 1 pushes the mark onto the y-axis, where
         * the label lands on top of `100%`. The shading and the
         * sentence below still say where the band starts; two strings
         * in the same 24 pixels say nothing.
         */
        ?>
        <?php if ($ttlX - $agingX >= 26 && $agingX - $left >= 26): ?>
            <text class="ttl-t" x="<?= $agingX - 3 ?>" y="18"
                  text-anchor="end"><?= h(sprintf(__('day %s'),
                      $agingDay)) ?></text>
        <?php endif; ?>
        <text class="ttl-t" x="<?= $ttlX - 3 ?>" y="18"
              text-anchor="end"><?= h(sprintf(__('day %s'),
                  $ttl)) ?></text>
        <?php if ($here !== null): ?>
            <circle class="ttl-here" cx="<?= $at($here['elapsed']) ?>"
                    cy="<?= $height($here['runway']) ?>" r="3.5" />
            <text class="ttl-t ttl-hl" x="<?= $at($here['elapsed']) + 5 ?>"
                  y="<?= $height($here['runway']) - 3 ?>">
                <?= h(sprintf(__('here — day %1$s, %2$s%%'),
                    $here['days'], $here['pct'])) ?>
            </text>
        <?php endif; ?>
        <text class="ttl-t" x="<?= $left ?>" y="106" text-anchor="middle">0</text>
        <text class="ttl-t" x="24" y="15" text-anchor="end">100%</text>
        <text class="ttl-t" x="24" y="99" text-anchor="end">0%</text>
    </svg>
    <p class="wb-sub mb-0">
        <?php
        /*
         * What the aging fraction works out to, said here rather than
         * under the box that holds it: the field's help is rendered
         * once with the section, this figure redraws on every edit, and
         * only one of the two can name a day without going stale the
         * moment the decay speed moves. `0.33` is not day 30 of 90
         * either — the speed bends the curve between them — which is
         * the whole reason the number is worth printing.
         *
         * *Aging starts on day 60* was the first wording and it is a
         * false statement about the line directly above it: the line
         * falls from day zero, which is what makes it a line. Nothing
         * starts on day 60 — that is where the label changes, from
         * `current` to `aging`, and `aging` is not `expired` either.
         */
        ?>
        <?= h(sprintf(
            __('It loses relevance from day zero. Current until day'
                . ' %1$s, then aging — still inside its lifetime —'
                . ' until day %2$s, and expired after that.'),
            $agingDay,
            $ttl
        )) ?>
        <?= $speed == 1
            ? h(__('Straight because decay speed is 1. Below 1 it bows up'
                . ' and falls off a cliff at the end; above 1 it drops at'
                . ' once and then lingers.'))
            : h(sprintf(__('Bowed because decay speed is %s. At 1 it is a'
                . ' straight line.'), $speed)) ?>
    </p>
</figure>
