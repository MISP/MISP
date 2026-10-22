<?php
$collection = $data['Collection'] ?? $data;
$description = trim((string)($collection['description'] ?? ''));
$canEdit = !empty($isSiteAdmin) || !empty($mayModify);
$editUrl = $baseurl . '/collections/edit/' . $collection['id'];
?>

<div class="card mb-3 border-0 shadow-sm overflow-hidden">
    <div style="height:3px;background:linear-gradient(90deg, var(--bs-primary), rgba(var(--bs-primary-rgb), 0));"></div>

    <?php if ($description !== ''): ?>
        <div class="card-body px-4 py-3">
            <div class="d-flex align-items-center gap-2 mb-2">
                <span class="d-inline-flex align-items-center justify-content-center rounded-circle bg-primary-subtle text-primary flex-shrink-0"
                      style="width:1.75rem;height:1.75rem;">
                    <i class="fas fa-align-left fa-xs"></i>
                </span>
                <span class="text-body-secondary small text-uppercase fw-bold"><?= __('Description') ?></span>
            </div>
            <p class="mb-0 fs-6 lh-lg text-body text-break">
                <?= nl2br(h($description)) ?>
            </p>
        </div>
    <?php else: ?>
        <div class="card-body d-flex flex-column align-items-center text-center gap-2 py-4">
            <span class="d-inline-flex align-items-center justify-content-center rounded-circle bg-body-tertiary text-body-secondary"
                  style="width:2.5rem;height:2.5rem;">
                <i class="fas fa-align-left"></i>
            </span>
            <div class="fw-semibold"><?= __('No description yet') ?></div>
            <div class="text-body-secondary small">
                <?= __('A short summary helps others understand what this collection gathers and why.') ?>
            </div>
            <?php if ($canEdit): ?>
                <a href="<?= h($editUrl) ?>"
                   class="btn btn-sm btn-outline-primary rounded-pill px-3 mt-1"
                   onclick="event.preventDefault(); openModal(this.href);">
                    <i class="fas fa-plus me-1"></i><?= __('Add a description') ?>
                </a>
            <?php endif; ?>
        </div>
    <?php endif; ?>
</div>
