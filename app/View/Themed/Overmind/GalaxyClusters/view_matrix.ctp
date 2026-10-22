<?php
/**
 * The cluster page's Matrix tab: one matrix galaxy at a time, its techniques
 * lit by the cluster's events (observed) or by its relations (declared).
 *
 * $view as ClusterMatrixTool::view() builds it.
 */
$clusterId = (int)$view['cluster']['id'];
$layer = $view['layer'];
$observed = $layer === 'observed';
$query = [
    'layer' => $layer,
    'similar' => $view['similar'] ? 1 : 0,
    'cap' => $view['cap'],
    'galaxy' => $view['galaxy'],
    'off' => implode(',', $view['off']),
    'tab' => $view['matrix']['tab'] ?? null,
];
$texts = [
    'onEvent' => __('On an event'),
    'eventOne' => __('On 1 event'),
    'eventMany' => __('On %s events'),
    'subOf' => __('Sub-technique of %s'),
    'throughOne' => __('Through 1 sub-technique'),
    'throughMany' => __('Through %s sub-techniques'),
    'open' => __('Open the technique'),
    'openSub' => __('Open %s'),
    'close' => __('Close'),
    'failed' => __('Could not load the matrix.'),
    'self' => __('This cluster'),
    'similar' => __('Similar to %s', $view['cluster']['value']),
    'via' => __('Through %s'),
    'linkOut' => __('{who} {relation} it'),
    'linkIn' => __('It {relation} {who}'),
    'eventsOne' => __('View the event'),
    'eventsMany' => __('View the %s events'),
];
$unusedId = 'mx-hide-unused-cluster-' . $clusterId;
$similarId = 'mx-similar-' . $clusterId;
$current = null;
foreach ($view['reach'] as $galaxy) {
    if ($galaxy['id'] === $view['galaxy']) {
        $current = $galaxy;
    }
}
$plural = function ($n, $one, $many) {
    return $n === 1 ? $one : sprintf($many, number_format($n));
};
?>
<div class="card shadow-sm mb-3 mx-inline mx-cluster" data-mx-inline data-mx-cap-store
     data-url="<?= h($baseurl . '/galaxy_clusters/viewMatrix/' . $clusterId) ?>"
     data-mx-query="<?= h(http_build_query(array_filter($query, function ($v) {
         return $v !== null && $v !== '';
     }))) ?>"
     data-mx-text="<?= h(json_encode($texts)) ?>">
    <div class="mx-cl-bar">
        <div class="mx-cl-seg" role="group" aria-label="<?= h(__('Layer')) ?>">
            <button type="button" data-mx-set="layer=observed" aria-pressed="<?= $observed ? 'true' : 'false' ?>"
                    title="<?= h(__('Techniques seen on the same events')) ?>">
                <i class="fas fa-eye" aria-hidden="true"></i><?= __('Observed') ?>
                <span class="mx-cl-n"><?= (int)$view['counts']['observed'] ?></span>
            </button>
            <button type="button" data-mx-set="layer=declared" aria-pressed="<?= $observed ? 'false' : 'true' ?>"
                    title="<?= h(__('Techniques linked by galaxy relations')) ?>">
                <i class="fas fa-link" aria-hidden="true"></i><?= __('Declared') ?>
                <span class="mx-cl-n"><?= (int)$view['counts']['declared'] ?></span>
            </button>
        </div>
        <?php if ($observed): ?>
        <div class="mx-cl-ctl">
            <label class="mx-cl-cap">
                <?= __('Latest') ?>
                <select class="form-select form-select-sm" data-mx-param="cap" aria-label="<?= h(__('How many events to read')) ?>">
                    <?php foreach ($view['caps'] as $cap): ?>
                    <option value="<?= (int)$cap ?>"<?= $cap === $view['cap'] ? ' selected' : '' ?>><?= number_format($cap) ?></option>
                    <?php endforeach; ?>
                </select>
                <?= __('events') ?>
            </label>
            <?php if ($view['capped']): ?>
            <span class="mx-cl-read is-capped"><i class="fas fa-scissors" aria-hidden="true"></i><?= __('Based on the latest %s events', number_format($view['cap'])) ?></span>
            <?php else: ?>
            <span class="mx-cl-read"><?= $plural($view['events'], __('From its only event'), __('From all %s events')) ?></span>
            <?php endif; ?>
        </div>
        <?php else: ?>
        <div class="mx-cl-ctl">
            <span><?= __('Relations') ?></span>
            <?php if (empty($view['relations'])): ?>
            <span class="mx-cl-none"><?= __('none in this matrix') ?></span>
            <?php endif; ?>
            <?php foreach ($view['relations'] as $relation => $n): ?>
            <button type="button" class="mx-cl-chip" data-mx-toggle-off="<?= h($relation) ?>"
                    aria-pressed="<?= in_array($relation, $view['off'], true) ? 'false' : 'true' ?>">
                <?= h($relation) ?><span class="mx-cl-n"><?= (int)$n ?></span>
            </button>
            <?php endforeach; ?>
        </div>
        <?php endif; ?>
        <div class="mx-cl-right">
            <div class="dropdown">
                <button type="button" class="mx-cl-btn dropdown-toggle" data-bs-toggle="dropdown" aria-expanded="false">
                    <i class="fas fa-layer-group" aria-hidden="true"></i><?= $plural(count($view['scope']), __('Counting 1 cluster'), __('Counting %s clusters')) ?>
                </button>
                <div class="dropdown-menu dropdown-menu-end mx-cl-scope">
                    <div class="dropdown-header"><?= __('Both layers read the events and relations of') ?></div>
                    <?php foreach ($view['scope'] as $member): ?>
                    <a class="dropdown-item" href="<?= h($baseurl . '/galaxy_clusters/view/' . (int)$member['id']) ?>">
                        <i class="fas <?= $member['self'] ? 'fa-location-crosshairs' : 'fa-equals' ?>" aria-hidden="true"></i>
                        <span><b><?= h($member['value']) ?></b><small><?= h($member['galaxy']) ?> · <?= $member['self'] ? __('this cluster') : __('similar') ?></small></span>
                    </a>
                    <?php endforeach; ?>
                </div>
            </div>
            <div class="form-check form-switch mx-cl-switch">
                <input class="form-check-input" type="checkbox" role="switch" id="<?= h($similarId) ?>" data-mx-param="similar"<?= $view['similar'] ? ' checked' : '' ?>>
                <label class="form-check-label" for="<?= h($similarId) ?>"><?= __('Include similar clusters') ?></label>
            </div>
            <?php if (count($view['reach']) > 1): ?>
            <div class="dropdown">
                <button type="button" class="mx-cl-btn dropdown-toggle" data-bs-toggle="dropdown" aria-expanded="false">
                    <i class="fas fa-table-cells" aria-hidden="true"></i><?= h($current['name'] ?? '') ?>
                </button>
                <div class="dropdown-menu dropdown-menu-end">
                    <?php foreach ($view['reach'] as $galaxy): ?>
                    <button type="button" class="dropdown-item mx-cl-galaxy<?= $galaxy['id'] === $view['galaxy'] ? ' active' : '' ?>" data-mx-set="galaxy=<?= (int)$galaxy['id'] ?>">
                        <span><?= h($galaxy['name']) ?></span><span class="mx-cl-n"><?= (int)$galaxy[$layer] ?></span>
                    </button>
                    <?php endforeach; ?>
                </div>
            </div>
            <?php endif; ?>
            <div class="form-check form-switch mx-modal-unused">
                <input class="form-check-input" type="checkbox" role="switch" id="<?= h($unusedId) ?>" data-mx-hide-unused>
                <label class="form-check-label" for="<?= h($unusedId) ?>"><?= __('Hide unused columns') ?></label>
            </div>
        </div>
    </div>
    <div data-mx-inline-body>
        <?php if ($view['matrix'] === null): ?>
        <div class="mx-full-empty">
            <?= __('Without similar clusters, nothing this cluster is linked to sits in a matrix.') ?>
            <button type="button" class="mx-include" data-mx-set="similar=1"><?= __('Include similar clusters') ?></button>
        </div>
        <?php else: ?>
        <?php if ((int)$view['counts'][$layer] === 0): ?>
        <div class="mx-cl-empty">
            <i class="fas fa-circle-info" aria-hidden="true"></i>
            <span><?= $observed
                ? h(__('No technique of this matrix was seen on the events of %s.', $view['cluster']['value']))
                : h(__('No relation links %s to a technique of this matrix.', $view['cluster']['value'])) ?></span>
            <?php if (!$view['similar']): ?>
            <button type="button" class="mx-include" data-mx-set="similar=1"><?= __('Include similar clusters') ?></button>
            <?php endif; ?>
        </div>
        <?php endif; ?>
        <?= $this->element('GalaxyMatrix/full', [
            'matrix' => $view['matrix'] + ['origins' => []],
            'lightIcon' => 'misp-icon misp-icon-attribute misp-simple',
            'marks' => $view['marks'],
            'counts' => $observed,
            'heat' => $observed,
        ]) ?>
        <?php endif; ?>
    </div>
</div>
