<?php
// view_layout only forwards `data` to the partial; pull the extra view vars the
// controller set() from the shared view vars.
$isSiteAdmin = $this->viewVars['isSiteAdmin'] ?? false;
$fullAccess = $this->viewVars['fullAccess'] ?? false;
$org = $data['Organisation'] ?? [];
$local = !empty($org['local']);

$domains = $org['restricted_to_domain'] ?? [];
if (is_array($domains)) {
    $domains = implode("\n", $domains);
}

// key => [label, value] rows for the metadata grid, only when populated.
$meta = [];
$meta[] = ['label' => __('ID'), 'value' => $org['id'] ?? ''];
if (!empty($org['uuid'])) {
    $meta[] = ['label' => __('UUID'), 'value' => $org['uuid'], 'mono' => true];
}
if (!empty(trim($org['nationality'] ?? ''))) {
    $flag = !empty($org['country_code']) ? $this->Icon->countryFlag($org['country_code']) . '&nbsp;' : '';
    $meta[] = ['label' => __('Nationality'), 'html' => $flag . h(trim($org['nationality']))];
}
foreach (['sector' => __('Sector'), 'type' => __('Organisation type'), 'contacts' => __('Contact information')] as $key => $label) {
    if (!empty(trim($org[$key] ?? ''))) {
        $meta[] = ['label' => $label, 'html' => nl2br(h(trim($org[$key])), false)];
    }
}
if (!empty($domains)) {
    $meta[] = ['label' => __('Domain restrictions'), 'html' => nl2br(h($domains), false)];
}
if ($isSiteAdmin) {
    $meta[] = ['label' => __('Created by'), 'value' => $org['created_by_email'] ?? __('Unknown')];
    if (!empty($org['date_created'])) {
        $meta[] = ['label' => __('Creation time'), 'value' => $org['date_created']];
    }
    if (!empty($org['date_modified'])) {
        $meta[] = ['label' => __('Last modified'), 'value' => $org['date_modified']];
    }
}
$logo = $this->OrgImg->getOrgLogo($data, 48, false);
?>
<div class="card mb-3 shadow-sm">
    <div class="card-body p-4">

        <div class="d-flex align-items-start justify-content-between mb-4">
            <!-- NAME + LOCAL/REMOTE -->
            <div>
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= __('Name') ?>
                </div>
                <div class="fw-semibold fs-5 d-flex align-items-center gap-2">
                    <?= h($org['name'] ?? '') ?>
                    <span class="badge <?= $local ? 'text-bg-success' : 'text-bg-secondary' ?>">
                        <?= $local ? __('Local') : __('Remote') ?>
                    </span>
                </div>
            </div>
            <?php if (!empty($logo)): ?>
                <div class="ms-3"><?= $logo ?></div>
            <?php endif; ?>
        </div>

        <?php if (!empty($org['description'])): ?>
            <div class="mb-4">
                <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Description') ?></div>
                <div><?= nl2br(h($org['description']), false) ?></div>
            </div>
        <?php endif; ?>

        <!-- META GRID -->
        <div class="row g-3">
            <?php foreach ($meta as $row): ?>
                <div class="col-md-6">
                    <div class="text-muted small text-uppercase fw-bold mb-1"><?= h($row['label']) ?></div>
                    <div class="bg-light rounded px-2 py-1 border <?= !empty($row['mono']) ? 'font-monospace' : '' ?>">
                        <?= isset($row['html']) ? $row['html'] : h($row['value']) ?>
                    </div>
                </div>
            <?php endforeach; ?>
        </div>

    </div>
</div>
