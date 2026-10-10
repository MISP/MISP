<?php

App::uses('ClassRegistry', 'Utility');

$eventId   = h($data['Event']['id'] ?? '');
$eventUuid = $data['Event']['uuid'] ?? '';
if ($eventUuid === '') {
    return;
}

$uid       = 'evt-analyst-' . $eventId;
$fetchUrl  = $baseurl . '/analystData/viewForObject/Event/'
    . rawurlencode($eventUuid) . '?embedded=1';
$analystCount = (int)ClassRegistry::init('Note')
    ->countForObjectRecursive($me, $eventUuid);

$canAdd = !empty($me['Role']['perm_analyst_data']);

$types = [
    'Note'         => [
        'color' => 'primary',
        'icon'  => 'misp-icon misp-icon-analyst-note misp-simple',
        'label' => __('Add note'),
    ],
    'Opinion'      => [
        'color' => 'success',
        'icon'  => 'misp-icon misp-icon-analyst-opinion misp-simple',
        'label' => __('Add opinion'),
    ],
    'Relationship' => [
        'color' => 'correlation',
        'icon'  => 'fas fa-diagram-project',
        'label' => __('Add relationship'),
    ],
];
?>

<div class="card shadow-sm mb-3" id="analyst-data-card">

    <!-- HEADER -->
    <div class="p-3 border-bottom">
        <div class="d-flex align-items-center gap-3 flex-wrap">

            <!-- Icon + title + count -->
            <div class="d-flex align-items-center gap-2 me-auto">
                <div class="rounded-2 d-flex align-items-center justify-content-center"
                     style="width:36px;height:36px;background:rgba(143,45,86,.12);">
                    <i class="fas fa-comment-dots text-analystData" style="font-size:1rem;"></i>
                </div>
                <div>
                    <div class="fw-bold lh-1"><?= __('Analyst data') ?></div>
                    <div class="small text-muted mt-1">
                        <?= $analystCount === 0
                            ? __('No analyst data')
                            : __n('%s entry', '%s entries', $analystCount, $analystCount) ?>
                    </div>
                </div>
            </div>

            <?php if ($canAdd): ?>
                <?php foreach ($types as $type => $meta): ?>
                    <?php $addUrl = h($baseurl . '/analystData/add/' . $type . '/'
                        . rawurlencode($eventUuid) . '/Event'); ?>
                    <button type="button"
                            class="btn btn-sm btn-outline-<?= h($meta['color']) ?> flex-shrink-0 d-flex align-items-center gap-1"
                            onclick="openModal('<?= $addUrl ?>')">
                        <i class="<?= h($meta['icon']) ?>"></i>
                        <?= h($meta['label']) ?>
                    </button>
                <?php endforeach; ?>
            <?php endif; ?>

        </div>
    </div>

    <!-- BODY -->
    <div id="<?= $uid ?>-body"
         data-collapse-tall="400">
        <div class="text-center py-4 text-muted">
            <div class="spinner-border spinner-border-sm" role="status"></div>
        </div>
    </div>

</div>

<script>
(function () {
    var uid      = <?= json_encode($uid) ?>;
    var fetchUrl = <?= json_encode($fetchUrl) ?>;
    var body     = document.getElementById(uid + '-body');
    if (!body) { return; }

    fetch(fetchUrl, { headers: { 'X-Requested-With': 'XMLHttpRequest' } })
        .then(function (r) {
            if (!r.ok) { throw new Error(r.status); }
            return r.text();
        })
        .then(function (html) {
            body.innerHTML = html;
        })
        .catch(function () {
            body.innerHTML =
                '<div class="text-center text-muted py-4 small">'
                + '<i class="fas fa-exclamation-triangle me-2"></i>'
                + <?= json_encode(__('Could not load analyst data.')) ?>
                + '</div>';
        });
}());
</script>
