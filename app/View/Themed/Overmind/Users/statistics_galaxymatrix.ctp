<?php
/**
 * Statistics galaxy matrix tab: a matrix galaxy's techniques shaded by the
 * events carrying them, on Overmind's matrix.
 *
 * $matrix             EventMatrixTool::usage() with the statistics counts
 * $matrixGalaxies     the matrix galaxies the user can pick
 * $organisations      id => name, 0 for all of them
 * $pickedOrganisation $dateFrom $dateTo  the filters applied
 * $matrixUrl          this tab with its filters, which the matrix reloads its tabs from
 */
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
];
$galaxyId = (int)$matrix['galaxy']['id'];
$uid = 'stats-matrix-' . mt_rand();
$filtered = $pickedOrganisation !== 0 || $dateFrom !== '' || $dateTo !== '';
?>
<div class="card shadow-sm mb-3" id="<?= h($uid) ?>">
    <div class="card-body">
        <form class="row g-2 align-items-end" data-matrix-filters>
            <div class="col-md-4">
                <label class="form-label small mb-1" for="<?= h($uid) ?>-galaxy"><?= __('Galaxy') ?></label>
                <select class="form-select form-select-sm" id="<?= h($uid) ?>-galaxy" name="galaxy_id">
                    <?php foreach ($matrixGalaxies as $galaxy): ?>
                    <option value="<?= (int)$galaxy['Galaxy']['id'] ?>"<?= (int)$galaxy['Galaxy']['id'] === $galaxyId ? ' selected' : '' ?>><?= h($galaxy['Galaxy']['name']) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="col-md-3">
                <label class="form-label small mb-1" for="<?= h($uid) ?>-org"><?= __('Creator organisation') ?></label>
                <select class="form-select form-select-sm" id="<?= h($uid) ?>-org" name="organisation">
                    <?php foreach ($organisations as $id => $name): ?>
                    <option value="<?= (int)$id ?>"<?= (int)$id === $pickedOrganisation ? ' selected' : '' ?>><?= h($name) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="col-6 col-md-2">
                <label class="form-label small mb-1" for="<?= h($uid) ?>-from"><?= __('From') ?></label>
                <input type="date" class="form-control form-control-sm" id="<?= h($uid) ?>-from" name="dateFrom" value="<?= h($dateFrom) ?>">
            </div>
            <div class="col-6 col-md-2">
                <label class="form-label small mb-1" for="<?= h($uid) ?>-to"><?= __('To') ?></label>
                <input type="date" class="form-control form-control-sm" id="<?= h($uid) ?>-to" name="dateTo" value="<?= h($dateTo) ?>">
            </div>
            <div class="col-md-1">
                <button type="submit" class="btn btn-primary btn-sm w-100"><?= __('Apply') ?></button>
            </div>
        </form>
        <p class="small text-body-secondary mt-2 mb-0">
            <?= $filtered
                ? __('Counting the events you can see that match the filters.')
                : __('Counting every event on this instance that carries the technique, on the event or on one of its attributes.') ?>
        </p>
    </div>
</div>
<div class="card shadow-sm mb-3 mx-inline" data-mx-inline
     data-url="<?= h($matrixUrl) ?>"
     data-mx-text="<?= h(json_encode($texts)) ?>">
    <div class="mx-inline-head">
        <div class="mx-modal-legend">
            <span><?= __('Fewer events') ?></span>
            <?php foreach ([12, 28, 44, 60] as $shade): ?>
            <span class="mx-sw" style="background: color-mix(in srgb, var(--bs-galaxy) <?= $shade ?>%, var(--bs-body-bg));"></span>
            <?php endforeach; ?>
            <span><?= __('More events') ?></span>
        </div>
        <div class="form-check form-switch mx-modal-unused">
            <input class="form-check-input" type="checkbox" role="switch" id="<?= h($uid) ?>-unused" data-mx-hide-unused>
            <label class="form-check-label" for="<?= h($uid) ?>-unused"><?= __('Hide unused columns') ?></label>
        </div>
    </div>
    <div data-mx-inline-body>
        <?= $this->element('GalaxyMatrix/full', [
            'matrix' => $matrix,
            'lightIcon' => 'misp-icon misp-icon-attribute misp-simple',
            'heat' => true,
        ]) ?>
    </div>
</div>
<script>
(function () {
    var card = document.getElementById(<?= json_encode($uid) ?>);
    card.querySelector('[data-matrix-filters]').addEventListener('submit', function (event) {
        event.preventDefault();
        var url = <?= json_encode($baseurl . '/users/statistics/galaxyMatrix') ?>;
        new FormData(event.target).forEach(function (value, name) {
            if (value !== '' && !(name === 'organisation' && value === '0')) {
                url += '/' + name + ':' + encodeURIComponent(value);
            }
        });
        reloadAjaxTabIndex(card.closest('.ajax-tab-content'), url);
    });
})();
</script>
