<?php
/**
 * Whether this hash is something somebody shipped.
 *
 * The known-malicious case takes the widget over rather than sitting
 * beside the package name: a service saying a hash is known-bad has
 * said the strongest thing it can say, and a widget headed *libc6*
 * with a warning underneath reads as a package with a note on it.
 *
 * @var array $data
 */
$record = $data['headline'];
?>
<div class="vp-rw-in vp-rw-known">
    <?php if ($data['malicious'] !== null): ?>
        <div class="vp-rw-verdict vp-rw-v-mal"><?=
            h(__('known bad')) ?></div>
        <div class="vp-rw-sub"><?= h($data['malicious']) ?></div>
    <?php elseif ($data['known']): ?>
        <div class="vp-rw-verdict vp-rw-v-ben"><?=
            h(__('known good')) ?></div>
        <?php if ($record['package'] !== null): ?>
            <div class="vp-rw-sub" title="<?=
                h($record['package']) ?>"><?= h($record['package']) ?></div>
        <?php elseif ($record['name'] !== null): ?>
            <div class="vp-rw-sub font-monospace" title="<?=
                h($record['name']) ?>"><?= h($record['name']) ?></div>
        <?php endif; ?>
        <?php if ($record['source'] !== null): ?>
            <div class="vp-rw-note"><?= h($record['source']) ?></div>
        <?php endif; ?>
    <?php else: ?>
        <div class="vp-rw-head vp-rw-quiet"><?= h(__('recorded')) ?></div>
    <?php endif; ?>
</div>
