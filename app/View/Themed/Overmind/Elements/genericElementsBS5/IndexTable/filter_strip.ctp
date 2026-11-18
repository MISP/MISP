<?php
/**
 * The strip a `time` child draws across its bar when it brings
 * `histograms`: how many rows fall on each day, week or month of one of its
 * dates, a switch between those dates, and a brush. Heights follow the
 * square root of the count, so a quiet day beside a burst still shows; the
 * caption names the count under the pointer. A drag keeps the period
 * it covers, as the child's own field; a click drops it (index-filters.js,
 * misp-brush.js). The child's picker in the panel still takes exact dates.
 *
 * - histograms : field name => {histogram: ValueStatsTool::timeHistogram()
 *                plus its `scale`, or null when no row carries the date;
 *                unset: how many rows do not}
 *
 * @var array $child
 * @var IndexFilterState $state
 */
$grains = [
    'day' => __('one bar a day'),
    'week' => __('one bar a week'),
    'month' => __('one bar a month'),
];

// A field's filter as the first and last day it keeps; null when unset.
$boundsOf = function ($name) use ($state) {
    $value = $state->getList($name) ?? $state->get($name);
    if ($value === null || $value === '') {
        return null;
    }
    if (is_string($value) && strpos($value, '||') !== false) {
        $value = explode('||', $value, 2);
    }
    $day = function ($text) {
        $text = trim((string)$text);
        if ($text === '' || $text === '0') {
            return null;
        }
        if (preg_match('/^(\d+)d$/', $text, $match)) {
            return date('Y-m-d', strtotime('-' . (int)$match[1] . ' days'));
        }
        $time = ctype_digit($text) ? (int)$text : strtotime($text);
        return $time ? date('Y-m-d', $time) : null;
    };
    return is_array($value)
        ? [$day($value[0] ?? ''), $day($value[1] ?? '')]
        : [$day($value), null];
};

$fields = [];
$shown = null;
foreach ($child['fields'] as $field) {
    if (!array_key_exists($field['name'], $child['histograms'])) {
        continue;
    }
    $field += $child['histograms'][$field['name']];
    $field['bounds'] = $boundsOf($field['name']);
    if ($shown === null && $field['bounds'] !== null) {
        $shown = $field['name'];
    }
    $fields[] = $field;
}
if (empty($fields)) {
    return;
}
$shown = $shown ?? $fields[0]['name'];
?>
<div class="ifp-strip" data-ifp-swap="strip-<?= h($child['name']) ?>" data-ifp-strip="<?= h(json_encode([
    'row' => __('1 row'),
    'rows' => __('%s rows'),
    'kept' => __('%s · a click drops the period'),
], JSON_UNESCAPED_UNICODE)) ?>">
    <div class="ifp-strip-head">
        <span class="ifp-strip-k">
            <?php if (!empty($child['icon'])): ?>
                <i class="<?= h($child['icon']) ?>" aria-hidden="true"></i>
            <?php endif; ?>
            <?= h($child['strip_label'] ?? $child['label']) ?>
        </span>
        <?php if (count($fields) > 1): ?>
            <div class="ifp-strip-seg" role="group" aria-label="<?= h(__('Which date')) ?>">
                <?php foreach ($fields as $field): ?>
                    <button type="button" class="ifp-strip-btn<?= $field['name'] === $shown ? ' active' : '' ?>"
                            data-ifp-strip-field="<?= h($field['name']) ?>"
                            aria-pressed="<?= $field['name'] === $shown ? 'true' : 'false' ?>"><?= h($field['label']) ?></button>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>
        <span class="ifp-strip-cap" data-ifp-strip-cap aria-live="polite"></span>
    </div>
    <?php foreach ($fields as $field): ?>
        <?php
        $histogram = $field['histogram'];
        $unset = (int)($field['unset'] ?? 0);
        $selection = '';
        $rest = '';
        if ($histogram !== null) {
            $bars = $histogram['bars'];
            $last = count($bars) - 1;
            // A week is named by its days, so a run of weeks reads from its first day to its last.
            foreach ($bars as $at => $bar) {
                $weekly = $histogram['unit'] === 'week';
                $bars[$at]['start'] = $weekly ? date('j M Y', strtotime($bar['from'])) : $bar['label'];
                $bars[$at]['end'] = $weekly ? date('j M Y', strtotime($bar['to'])) : $bar['label'];
            }
            $rest = sprintf(
                __('%1$s – %2$s · %3$s · drag to keep a period'),
                $bars[0]['start'],
                $bars[$last]['end'],
                $grains[$histogram['unit']] ?? ''
            );
            if ($field['bounds'] !== null) {
                [$from, $to] = $field['bounds'];
                $first = null;
                $end = null;
                foreach ($bars as $at => $bar) {
                    $inside = ($from === null || $bar['to'] >= $from) && ($to === null || $bar['from'] <= $to);
                    if ($inside) {
                        $first = $first ?? $at;
                        $end = $at;
                    }
                }
                $selection = $first === null ? 'none' : $first . ',' . $end;
            }
        }
        if ($unset > 0) {
            $rest = trim($rest . ' · ' . sprintf(__n('%s row without this date', '%s rows without this date', $unset), number_format($unset)), ' ·');
        }
        ?>
        <div class="ifp-strip-pane" data-ifp-strip-pane="<?= h($field['name']) ?>"
             data-ifp-strip-rest="<?= h($rest) ?>"<?=
             $selection === '' ? '' : ' data-ifp-strip-sel="' . h($selection) . '"' ?><?=
             $field['name'] === $shown ? '' : ' hidden' ?>>
            <?php if ($histogram === null): ?>
                <div class="ifp-strip-none"><?= h(__('No row carries this date.')) ?></div>
            <?php else: ?>
                <div class="ifp-strip-chart">
                    <div class="ifp-strip-bars" role="img" aria-label="<?= h(sprintf(__('%1$s, %2$s.'), $field['label'], $grains[$histogram['unit']] ?? '')) ?>">
                        <?php foreach ($bars as $bar): ?>
                            <i<?= $bar['count'] === 0 ? ' class="is-zero"' : '' ?>
                               style="height: <?= $bar['count'] === 0 ? 0 : max(8, round(sqrt($bar['count'] / max(1, $histogram['max'])) * 100)) ?>%;"
                               data-ifp-from="<?= h($bar['from']) ?>" data-ifp-to="<?= h($bar['to']) ?>"
                               data-ifp-label="<?= h($bar['label']) ?>" data-ifp-start="<?= h($bar['start']) ?>"
                               data-ifp-end="<?= h($bar['end']) ?>" data-ifp-count="<?= (int)$bar['count'] ?>"></i>
                        <?php endforeach; ?>
                    </div>
                    <?= $this->element('genericElementsBS5/brush') ?>
                </div>
                <div class="ifp-strip-axis" aria-hidden="true">
                    <?php foreach (($histogram['scale'] ?? []) as $at => $label): ?>
                        <?php if ($label !== null): ?>
                            <span style="left: <?= h(round($at / count($bars) * 100, 2)) ?>%;"><?= h($label) ?></span>
                        <?php endif; ?>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
        </div>
    <?php endforeach; ?>
</div>
