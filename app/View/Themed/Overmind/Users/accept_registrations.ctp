<?php
$permChip = function ($color, $icon, $label) {
    return sprintf(
        '<span class="d-inline-flex align-items-center gap-2">'
            . '<span class="d-inline-flex align-items-center justify-content-center rounded-2 text-bg-%s text-white flex-shrink-0" style="width:1.5rem; height:1.5rem;">'
            . '<i class="fas %s" style="font-size:.8rem;"></i></span>'
            . '<span class="fw-semibold text-body">%s</span></span>',
        $color,
        $icon,
        h($label)
    );
};
$permMeta = [
    'perm_publish' => ['success', 'fa-upload', __('Publish')],
    'perm_sync'    => ['warning', 'fa-arrows-rotate', __('Sync')],
    'perm_admin'   => ['primary', 'fa-user-shield', __('Org admin')],
];
?>

<div class="container-fluid my-3">
    <div class="d-flex align-items-center justify-content-between mb-3">
        <h4 class="mb-0 fw-semibold">
            <i class="fas fa-user-check text-primary me-2"></i><?= __('Accept registrations') ?>
        </h4>
        <span class="badge text-bg-secondary">
            <?= __n('%d request', '%d requests', count($registrations), count($registrations)) ?>
        </span>
    </div>

    <?php
    echo $this->Form->create('User', [
        'id' => 'AcceptRegistrationsForm',
        'url' => $baseurl . '/users/acceptRegistrations/' . $id,
        'novalidate' => true,
    ]);
    ?>

    <div class="d-flex flex-column gap-3" style="max-height: 65vh; overflow-y: auto;">
        <?php foreach ($registrations as $reg):
            $rid = $reg['Inbox']['id'];
            $d = $reg['Inbox']['data'];
            $email = $d['email'] ?? '';
            $reqOrgName = $d['org_name'] ?? '';
            $reqOrgUuid = $d['org_uuid'] ?? '';
            $so = $reg['suggestedOrg'] ?? null;

            // Requested-permission chips (only when a custom role was requested).
            $reqPerms = [];
            if (!empty($d['custom_perms'])) {
                foreach (['perm_publish', 'perm_sync', 'perm_admin'] as $p) {
                    $reqPerms[$p] = !empty($d[$p]) ? 1 : 0;
                }
            }
        ?>
            <div class="card shadow-sm">
                <div class="card-header d-flex align-items-center gap-2 bg-light">
                    <i class="fas fa-user-plus text-primary"></i>
                    <span class="fw-semibold"><?= h($email) ?></span>
                </div>
                <div class="card-body">

                    <!-- Requested details -->
                    <div class="mb-3">
                        <div class="small text-muted mb-1"><?= __('Requested') ?></div>
                        <div class="d-flex flex-wrap align-items-center gap-3">
                            <div class="d-flex align-items-center gap-2">
                                <i class="fas fa-building text-secondary"></i>
                                <?php if ($reqOrgName !== '' || $reqOrgUuid !== ''): ?>
                                    <?php if ($reqOrgName !== ''): ?>
                                        <span><?= h($reqOrgName) ?></span>
                                    <?php endif; ?>
                                    <?php if ($reqOrgUuid !== ''): ?>
                                        <span class="badge text-bg-light border font-monospace"><?= h($reqOrgUuid) ?></span>
                                    <?php endif; ?>
                                <?php else: ?>
                                    <span class="text-body-secondary fst-italic"><?= __('No organisation preference') ?></span>
                                <?php endif; ?>
                            </div>
                            <div class="d-flex flex-wrap align-items-center gap-2">
                                <?php if (empty($reqPerms)): ?>
                                    <?= $permChip('secondary', 'fa-user', __('Default role')) ?>
                                <?php else: ?>
                                    <?php
                                    $any = false;
                                    foreach ($permMeta as $k => $meta) {
                                        if (!empty($reqPerms[$k])) {
                                            echo $permChip($meta[0], $meta[1], $meta[2]);
                                            $any = true;
                                        }
                                    }
                                    if (!$any) {
                                        echo $permChip('dark', 'fa-user-pen', __('Custom role'));
                                    }
                                    ?>
                                <?php endif; ?>
                            </div>
                        </div>

                        <?php if ($so === false): ?>
                            <div class="alert alert-warning d-flex align-items-center gap-2 py-1 px-2 mt-2 mb-0 small" role="alert">
                                <i class="fas fa-triangle-exclamation"></i>
                                <?= __('Conflicting organisation requirements — choose one manually.') ?>
                            </div>
                        <?php elseif ($so === -1): ?>
                            <div class="alert alert-warning d-flex align-items-center gap-2 py-1 px-2 mt-2 mb-0 small" role="alert">
                                <i class="fas fa-triangle-exclamation"></i>
                                <?= __('Requested organisation not found — pick one below or create it first.') ?>
                            </div>
                        <?php endif; ?>
                    </div>

                    <!-- Assignment -->
                    <div class="row g-3">
                        <div class="col-md-6">
                            <label class="form-label fw-semibold" for="UserOrg<?= h($rid) ?>">
                                <?= __('Organisation') ?> <span class="text-danger">*</span>
                            </label>
                            <?= $this->Form->select('User.' . $rid . '.org_id', $orgs, [
                                'id' => 'UserOrg' . $rid,
                                'class' => 'form-select',
                                'empty' => __('Choose an organisation…'),
                            ]) ?>
                        </div>
                        <div class="col-md-6">
                            <label class="form-label fw-semibold" for="UserRole<?= h($rid) ?>">
                                <?= __('Role') ?> <span class="text-danger">*</span>
                            </label>
                            <?= $this->Form->select('User.' . $rid . '.role_id', $roles, [
                                'id' => 'UserRole' . $rid,
                                'class' => 'form-select role-select',
                                'empty' => false,
                                'data-requested' => json_encode($reqPerms),
                            ]) ?>
                            <div class="perm-hint small mt-1"></div>
                        </div>
                    </div>

                </div>
            </div>
        <?php endforeach; ?>
    </div>

    <div class="d-flex justify-content-end gap-2 mt-3">
        <button type="button" class="btn btn-outline-secondary"
                onclick="bootstrap.Modal.getInstance(document.getElementById('mainModal')).hide();">
            <?= __('Cancel') ?>
        </button>
        <button type="submit" class="btn btn-primary">
            <i class="fas fa-check me-1"></i><?= __('Accept all') ?>
        </button>
    </div>

    <?= $this->Form->end(); ?>
</div>

<script>
(function () {
    var form = document.getElementById('AcceptRegistrationsForm');
    if (!form) {
        return;
    }

    // Per-card hint: warn when the chosen role lacks a requested permission.
    var rolePerms = <?= json_encode($role_perms) ?>;
    var okText = <?= json_encode(__('This role satisfies the request')) ?>;
    var warnText = <?= json_encode(__('This role is missing a requested permission')) ?>;
    form.querySelectorAll('.role-select').forEach(function (sel) {
        var body = sel.closest('.card-body');
        var hint = body ? body.querySelector('.perm-hint') : null;
        var requested = {};
        try { requested = JSON.parse(sel.dataset.requested || '{}'); } catch (e) {}
        function update() {
            if (!hint) {
                return;
            }
            var keys = Object.keys(requested);
            if (keys.length === 0) {
                hint.innerHTML = '';
                return;
            }
            var perms = rolePerms[sel.value] || {};
            var missing = keys.some(function (k) {
                return Number(requested[k]) === 1 && Number(perms[k]) !== 1;
            });
            hint.innerHTML = missing
                ? '<span class="text-warning"><i class="fas fa-triangle-exclamation me-1"></i>' + warnText + '</span>'
                : '<span class="text-success"><i class="fas fa-check me-1"></i>' + okText + '</span>';
        }
        sel.addEventListener('change', update);
        update();
    });

    // AJAX submit — the action returns {saved, success|errors} JSON.
    form.addEventListener('submit', function (e) {
        e.preventDefault();
        var submitBtn = form.querySelector('button[type="submit"]');
        if (submitBtn) {
            submitBtn.disabled = true;
        }
        fetch(form.getAttribute('action'), {
            method: 'POST',
            headers: {
                'X-Requested-With': 'XMLHttpRequest',
                'Accept': 'application/json',
                'X-CSRF-Token': (typeof getCsrfToken === 'function' ? getCsrfToken() : '')
            },
            body: new URLSearchParams(new FormData(form))
        })
        .then(function (r) { return r.json().catch(function () { return {}; }); })
        .then(function (resp) {
            if (resp && resp.saved) {
                showToast(resp.success || <?= json_encode(__('Registrations accepted.')) ?>, 'success');
                var modal = bootstrap.Modal.getInstance(document.getElementById('mainModal'));
                if (modal) {
                    modal.hide();
                }
                setTimeout(function () { window.location.reload(); }, 600);
            } else {
                if (submitBtn) {
                    submitBtn.disabled = false;
                }
                showToast((resp && resp.errors) ? resp.errors : <?= json_encode(__('Could not accept the registrations.')) ?>, 'danger');
            }
        })
        .catch(function () {
            if (submitBtn) {
                submitBtn.disabled = false;
            }
            showToast(<?= json_encode(__('Could not accept the registrations.')) ?>, 'danger');
        });
    });
})();
</script>
