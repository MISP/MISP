<?php
$tpl = $data['EventTemplate'] ?? [];
$org = $data['Organisation'] ?? [];
$creator = $data['CreatorUser'] ?? [];
$deps = $data['EventTemplateObjectDependency'] ?? [];

$templateId = $tpl['id'] ?? '';
$templateUuid = $tpl['uuid'] ?? '';
$templateName = $tpl['name'] ?? __('Event Template');
$distribution = (int)($tpl['distribution'] ?? 0);
$active = (int)($tpl['active'] ?? 0) === 1;

$definitionJson = is_array($tpl['definition'] ?? null)
    ? JsonTool::encode($tpl['definition'], true)
    : (string)($tpl['definition'] ?? '');

$canInstantiate = $this->Acl->canAccess('eventTemplates', 'instantiate');
$canEdit = $this->Acl->canAccess('eventTemplates', 'edit');
$canDuplicate = $this->Acl->canAccess('eventTemplates', 'duplicate');
$canDelete = $this->Acl->canAccess('eventTemplates', 'delete');

$headerActions = [];
if ($canInstantiate) {
    $headerActions[] = [
        'type' => 'link',
        'label' => __('Create event from template'),
        'icon' => 'play',
        'url' => $baseurl . '/event_templates/instantiate/' . h($templateId),
    ];
}
if ($canEdit) {
    $headerActions[] = [
        'type' => 'link',
        'label' => __('Edit'),
        'icon' => 'pen-to-square',
        'url' => $baseurl . '/event_templates/edit/' . h($templateId),
    ];
}
$headerActions[] = [
    'type' => 'link',
    'label' => __('Export'),
    'icon' => 'download',
    'url' => $baseurl . '/event_templates/export/' . h($templateId),
];
$this->set('headerActions', $headerActions);
?>

<div class="container-fluid mt-3">

    <div class="card mb-3 shadow-sm">
        <div class="card-body">

            <div class="mb-4">
                <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Name') ?></div>
                <div class="fw-semibold fs-5"><?= h($templateName) ?></div>
            </div>

            <?php if (!empty($tpl['description'])): ?>
                <div class="mb-4">
                    <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Description') ?></div>
                    <div class="bg-light border rounded p-3"><?= nl2br(h($tpl['description'])) ?></div>
                </div>
            <?php endif; ?>

            <div class="row g-3">
                <div class="col-md-4">
                    <div class="text-muted small text-uppercase fw-bold mb-1">ID</div>
                    <div class="bg-light rounded px-2 py-1 d-inline-block"><?= h($templateId) ?></div>
                </div>

                <div class="col-md-4">
                    <div class="text-muted small text-uppercase fw-bold mb-1">UUID</div>
                    <div class="d-flex align-items-center gap-2">
                        <div class="bg-light rounded px-2 py-1"><?= h($templateUuid) ?></div>
                        <button
                            class="text-muted border-0 bg-white"
                            onclick="copyToClipboard('<?= h($templateUuid) ?>')"
                            title="<?= __('Copy UUID') ?>"
                            aria-label="<?= __('Copy UUID') ?>">
                            <i class="fas fa-copy"></i>
                        </button>
                    </div>
                </div>

                <div class="col-md-4">
                    <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Distribution') ?></div>
                    <?= $this->element('genericElementsBS5/Badges/distribution', [
                        'distribution' => $distribution,
                        'full' => true,
                    ]) ?>
                </div>

                <div class="col-md-4">
                    <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Organisation') ?></div>
                    <div><?= h($org['name'] ?? '') ?></div>
                </div>

                <div class="col-md-4">
                    <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Creator') ?></div>
                    <div><?= h($creator['email'] ?? '') ?></div>
                </div>

                <div class="col-md-4">
                    <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Active') ?></div>
                    <div>
                        <?php if ($active): ?>
                            <span class="badge bg-success"><i class="fas fa-check me-1"></i><?= __('Yes') ?></span>
                        <?php else: ?>
                            <span class="badge bg-secondary"><i class="fas fa-times me-1"></i><?= __('No') ?></span>
                        <?php endif; ?>
                    </div>
                </div>

                <div class="col-md-4">
                    <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Version') ?></div>
                    <div class="bg-light rounded px-2 py-1 d-inline-block"><?= h($tpl['version'] ?? '') ?></div>
                </div>

                <div class="col-md-4">
                    <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Created') ?></div>
                    <div><?= h($tpl['created'] ?? '') ?></div>
                </div>

                <div class="col-md-4">
                    <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Modified') ?></div>
                    <div><?= h($tpl['modified'] ?? '') ?></div>
                </div>
            </div>

        </div>
    </div>

    <div class="card mb-3 shadow-sm">
        <div class="card-header bg-white fw-semibold">
            <i class="fas fa-link me-2"></i><?= __('Object template dependencies') ?>
        </div>
        <div class="card-body">
            <?php if (empty($deps)): ?>
                <div class="text-muted fst-italic">
                    <?= __('None — this template does not reference any MISP objects.') ?>
                </div>
            <?php else: ?>
                <div class="table-responsive">
                    <table class="table table-sm table-hover mb-0">
                        <thead>
                            <tr>
                                <th><?= __('Object template name') ?></th>
                                <th><?= __('Object template UUID') ?></th>
                                <th class="text-end"><?= __('Minimum version') ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($deps as $dep): ?>
                                <tr>
                                    <td><?= h($dep['object_template_name'] ?? '') ?></td>
                                    <td><code><?= h($dep['object_template_uuid'] ?? '') ?></code></td>
                                    <td class="text-end"><?= (int)($dep['minimum_version'] ?? 0) ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            <?php endif; ?>
        </div>
    </div>

    <div class="card mb-3 shadow-sm">
        <div class="card-header bg-white fw-semibold d-flex justify-content-between align-items-center">
            <span>
                <i class="fas fa-code me-2"></i><?= __('Definition (JSON)') ?>
            </span>
            <?php if ($canEdit): ?>
                <a href="<?= $baseurl ?>/event_templates/edit/<?= h($templateId) ?>"
                   class="btn btn-sm btn-outline-primary">
                    <i class="fas fa-pen-to-square me-1"></i><?= __('Open in builder') ?>
                </a>
            <?php endif; ?>
        </div>
        <div class="card-body p-0">
            <pre class="mb-0 p-3 bg-light"
                 style="max-height:500px;overflow:auto;font-size:0.85rem;"><?= h($definitionJson) ?></pre>
        </div>
    </div>

</div>
