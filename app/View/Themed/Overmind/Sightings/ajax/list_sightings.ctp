<?php

$deleteSightingTitle = __('Delete sighting');
$types = isset($types) ? $types : ['Sighting', 'False-positive', 'Expiration'];
$typeColors = ['success', 'danger', 'warning'];
?>

<div class="table-responsive">
    <table class="table table-sm table-hover align-middle mb-0">
        <thead class="table-light">
            <tr>
                <th class="small"><?= __('Date') ?></th>
                <th class="small"><?= __('Organisation') ?></th>
                <th class="small"><?= __('Type') ?></th>
                <th class="small"><?= __('Source') ?></th>
                <th class="small"><?= __('Event') ?></th>
                <th class="small"><?= __('Attr') ?></th>
                <th></th>
            </tr>
        </thead>
        <tbody>
        <?php if (empty($sightings)): ?>
            <tr>
                <td colspan="7" class="text-center text-muted py-4">
                    <i class="fas fa-eye-slash me-1"></i><?= __('No sightings found') ?>
                </td>
            </tr>
        <?php else: ?>
            <?php foreach ($sightings as $item): ?>
            <?php
                $typeIdx   = intval($item['Sighting']['type']);
                $typeColor = $typeColors[$typeIdx] ?? 'secondary';
                $typeLabel = $types[$typeIdx] ?? $typeIdx;
            ?>
            <tr data-sighting-id="<?= h($item['Sighting']['id']) ?>">
                <td class="small text-nowrap"><?= $this->Time->time($item['Sighting']['date_sighting']) ?></td>
                <td>
                    <?php if (!empty($item['Organisation']['name'])): ?>
                        <span class="d-inline-flex align-items-center gap-1">
                            <?= $this->OrgImg->getOrgImg(['name' => $item['Organisation']['name'], 'id' => $item['Sighting']['org_id'], 'size' => 20]) ?>
                            <small class="text-muted"><?= h($item['Organisation']['name']) ?></small>
                        </span>
                    <?php endif; ?>
                </td>
                <td>
                    <span class="badge text-bg-<?= $typeColor ?> rounded-pill">
                        <?= h($typeLabel) ?>
                    </span>
                </td>
                <td class="small text-muted"><?= h($item['Sighting']['source']) ?></td>
                <td class="small">
                    <?php if (!empty($item['Sighting']['event_id'])): ?>
                        <a href="<?= $baseurl ?>/events/view2/<?= h($item['Sighting']['event_id']) ?>"
                           class="text-decoration-none">#<?= h($item['Sighting']['event_id']) ?></a>
                    <?php endif; ?>
                </td>
                <td class="small text-muted"><?= h($item['Sighting']['attribute_id']) ?></td>
                <td class="text-end">
                    <?php if ($this->Acl->canDeleteSighting($item)): ?>
                        <button class="btn btn-link btn-sm p-0 text-danger sighting-del"
                                data-sighting-id="<?= h($item['Sighting']['id']) ?>"
                                data-raw-id="<?= h($rawId) ?>"
                                data-context="<?= h($context) ?>"
                                title="<?= $deleteSightingTitle ?>"
                                aria-label="<?= $deleteSightingTitle ?>">
                            <i class="fas fa-trash-alt small"></i>
                        </button>
                    <?php endif; ?>
                </td>
            </tr>
            <?php endforeach; ?>
        <?php endif; ?>
        </tbody>
    </table>
</div>

<script>
(function () {
    var _msgConfirm = <?= json_encode(__('Are you sure you want to delete this sighting?')) ?>;
    var _msgTitle   = <?= json_encode(__('Delete sighting')) ?>;
    var _msgDel     = <?= json_encode(__('Delete')) ?>;
    var _msgCancel  = <?= json_encode(__('Cancel')) ?>;
    var _msgOk      = <?= json_encode(__('Sighting deleted')) ?>;
    var _msgFail    = <?= json_encode(__('Failed to delete sighting')) ?>;
    var _msgErr     = <?= json_encode(__('Request failed')) ?>;

    document.querySelectorAll('.sighting-del').forEach(function (btn) {
        btn.addEventListener('click', function () {
            var sid  = btn.dataset.sightingId;
            var rid  = btn.dataset.rawId;
            var ctx  = btn.dataset.context;

            showConfirmModal({
                title:        _msgTitle,
                body:         '<p class="text-muted mb-0">' + _msgConfirm + '</p>',
                confirmLabel: _msgDel,
                confirmClass: 'btn-danger',
                cancelLabel:  _msgCancel,
                onConfirm: async function () {
                    try {
                        var r = await fetch(
                            baseurl + '/sightings/quickDelete/' + sid + '/' + encodeURIComponent(rid) + '/' + ctx,
                            {
                                method: 'POST',
                                headers: {
                                    'X-Requested-With': 'XMLHttpRequest',
                                    'Accept':           'application/json',
                                    'X-CSRF-Token':     getCsrfToken(),
                                },
                            }
                        );
                        var data = await r.json();
                        if (data.saved) {
                            var row = document.querySelector('[data-sighting-id="' + sid + '"]');
                            if (row) row.remove();
                            showToast(_msgOk, 'success');
                        } else {
                            showToast(typeof data.errors === 'string' ? data.errors : _msgFail, 'danger');
                        }
                    } catch (_e) {
                        showToast(_msgErr, 'danger');
                    }
                }
            });
        });
    });
})();
</script>
