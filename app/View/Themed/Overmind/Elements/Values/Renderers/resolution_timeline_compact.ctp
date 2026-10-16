<?php
/**
 * What this name resolved to, as a shape over time or as a set.
 *
 * **Two widgets in one file, and the split is the data's.** A dated
 * answer gets a month-by-month strip of how many resolutions were
 * current; an undated one gets the addresses themselves with a count.
 * Drawing a strip for an undated answer would assert a history nobody
 * observed, and refusing to draw it at all would throw away the only
 * resolution answer a stock instance has.
 *
 * The strip is built from `months`, which `prepare()` computed and
 * filled — this template does no arithmetic beyond turning a count
 * into a percentage of the peak, which is drawing rather than
 * deciding.
 *
 * @var array $data
 */
$months = $data['months'];
$max = empty($months) ? 0 : max($months);
?>
<div class="vp-rw-in vp-rw-res">
    <div class="vp-rw-metric">
        <span class="vp-rw-metric-n"><?=
            h(number_format($data['distinct'])) ?></span>
        <span class="vp-rw-metric-l"><?= h(__n(
            'resolution', 'resolutions', $data['distinct']
        )) ?></span>
    </div>

    <?php if ($data['dated'] && $max > 0 && count($months) > 1): ?>
        <?php
        /*
         * One bar per month, which is the strip the Reporting and
         * Sightings cards draw their own months and buckets with. It
         * replaced a polyline on 2026-09-21 and the reason is that a
         * line between monthly counts draws a slope nobody measured:
         * a month is a bucket, not a sample, and between two of them
         * there is no path. Bars also survive the one case a line
         * cannot — an empty month, which the strip draws as a stub
         * and a line would step straight over.
         *
         * Scaled against the maximum alone, so a month with one
         * resolution against a peak of forty is a stub rather than
         * half the height. That is the opposite of what the polyline
         * did, and deliberately: a line had to spend its whole height
         * on the variation or read as flat, while a bar already has a
         * floor to be near.
         */
        $keys = array_keys($months);
        ?>
        <div class="vp-rw-months<?= count($months) > 48
            ? ' is-dense' : '' ?>" role="img" aria-label="<?= h(__(
            'Distinct resolutions current per month, oldest first'
        )) ?>">
            <?php foreach ($months as $month => $count): ?>
                <span class="vp-rw-month<?= $count === 0
                    ? ' vp-rw-month-empty' : '' ?>"
                      style="--vp-rw-month-h: <?=
                          h(round(100 * $count / $max)) ?>%;"
                      title="<?= h(sprintf(
                          __n(
                              '%2$s — %1$s resolution current',
                              '%2$s — %1$s resolutions current',
                              $count
                          ),
                          number_format($count),
                          $month
                      )) ?>"></span>
            <?php endforeach; ?>
        </div>
        <div class="vp-rw-sub vp-rw-ends"><?php
            foreach (array(reset($keys), end($keys)) as $end): ?>
            <span><?= h(date('M Y', strtotime($end . '-01'))) ?></span><?php
            endforeach; ?></div>
    <?php else: ?>
        <?php
        /*
         * The set, capped at what the height allows. Which three is
         * not an accident — `prepare()` sorted by how recently each
         * was current — and the count above already says how many
         * there are, so a `+N` here would say it twice.
         */
        $shown = array_slice($data['resolutions'], 0, 3);
        ?>
        <ul class="vp-rw-set">
            <?php foreach ($shown as $row): ?>
                <li class="font-monospace"><?= h($row['to']) ?><?php
                    if ($row['type'] !== ''): ?>
                    <span class="vp-rw-code"><?= h($row['type']) ?></span>
                <?php endif; ?></li>
            <?php endforeach; ?>
        </ul>
        <?php if (!$data['dated']): ?>
            <div class="vp-rw-note"><?= h(__('now, undated')) ?></div>
        <?php endif; ?>
    <?php endif; ?>
</div>
