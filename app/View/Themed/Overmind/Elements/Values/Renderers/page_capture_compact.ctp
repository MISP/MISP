<?php
/**
 * That a copy was taken, and when.
 *
 * **No thumbnail is drawn here.** A screenshot arrives as a link to
 * somebody else's server or as an attachment MISP holds behind an
 * authenticated route; the first would have five widgets in a row each
 * fetching an image from a third party on page load, which is the same
 * disclosure the enrichment gate exists to control, and the second
 * cannot be inlined from a pure template. The date and the URL are
 * what this size can honestly carry, and the picture is one click
 * away in the full rendering.
 *
 * @var array $data
 */
$capture = $data['newest'];
$when = $capture['captured'] !== null
    ? $capture['captured']
    : $capture['ran_at'];
?>
<div class="vp-rw-in vp-rw-cap">
    <div class="vp-rw-metric">
        <span class="vp-rw-metric-n"><?=
            h(number_format($data['count'])) ?></span>
        <span class="vp-rw-metric-l"><?= h(__n(
            'capture', 'captures', $data['count']
        )) ?></span>
    </div>
    <?php if ($when !== null): ?>
        <div class="vp-rw-sub"><?= h(date('Y-m-d', $when)) ?></div>
    <?php endif; ?>
    <?php if ($capture['url'] !== null): ?>
        <div class="vp-rw-note font-monospace" title="<?=
            h($capture['url']) ?>"><?= h($capture['url']) ?></div>
    <?php elseif ($capture['filename'] !== null): ?>
        <div class="vp-rw-note font-monospace"><?=
            h($capture['filename']) ?></div>
    <?php endif; ?>
</div>
