<?php
/**
 * Map tiles are off: the geolocation drawing stands in for the map, and
 * the tracks and areas are offered as their files.
 *
 * @var array $map the view model's `map`
 * @var array $origins
 */
?>
<div class="eov-notice">
    <i class="fas fa-map" aria-hidden="true"></i>
    <span><?= h(__('Map tiles are off on this instance, so the tracks and'
        . ' areas are not drawn. Their files:')) ?></span>
</div>
<ul class="eov-files">
    <?php foreach ($map['files'] as $file): ?>
        <?php $origin = $origins[$file['origin']] ?? null; ?>
        <li>
            <span class="eov-key eov-key-<?= $file['template'] === 'geojson'
                ? 'area' : 'track' ?>"></span>
            <span class="eov-lg-name" title="<?= h($file['name']) ?>"><?=
                h($file['name']) ?></span>
            <span class="eov-lg-meta"><?= h($file['template']) ?><?php
                if ($origin !== null): ?> · <a href="<?= h($baseurl
                    . '/objects/view/' . (int)$origin['object_id']) ?>"><?= h(
                    $origin['label'] ?? ($origin['template'] . ' #'
                        . $origin['object_id'])) ?></a><?php endif; ?></span>
            <a class="btn btn-sm btn-outline-secondary"
               href="<?= h($baseurl . '/attributes/download/'
                   . (int)$file['attachment']) ?>"
               download="<?= h($file['name']) ?>">
                <i class="fas fa-download me-1" aria-hidden="true"></i><?=
                h(__('Download')) ?>
            </a>
        </li>
    <?php endforeach; ?>
</ul>
