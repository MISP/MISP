<?php
$dependencies = $data['EventTemplateObjectDependency'] ?? [];
?>

<div class="card mb-3 shadow-sm">
    <div class="card-header bg-white fw-semibold">
        <i class="misp-icon misp-icon-object misp-simple me-2 text-object"></i>
        <?= __('Object template dependencies') ?>
    </div>
    <div class="card-body <?= empty($dependencies) ? 'p-4' : 'p-0' ?>">

        <?php if (empty($dependencies)): ?>
            <div class="text-muted fst-italic">
                <?= __('None — this template does not reference any MISP object.') ?>
            </div>
        <?php else: ?>
            <div class="table-responsive">
                <table class="table table-hover align-middle mb-0">
                    <thead>
                        <tr>
                            <th><?= __('Object template') ?></th>
                            <th>UUID</th>
                            <th class="text-end"><?= __('Minimum version') ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($dependencies as $dependency): ?>
                            <?php $dependencyUuid = (string)($dependency['object_template_uuid'] ?? ''); ?>
                            <tr>
                                <td class="fw-semibold">
                                    <i class="fas fa-cube text-muted me-2" style="font-size:.8rem;"></i>
                                    <?= h($dependency['object_template_name'] ?? '') ?>
                                </td>
                                <td>
                                    <div class="d-flex align-items-center gap-2">
                                        <code class="text-body"><?= h($dependencyUuid) ?></code>
                                        <button type="button"
                                                class="btn btn-sm btn-light border-0 text-muted"
                                                data-uuid="<?= h($dependencyUuid) ?>"
                                                onclick="copyValueToClipboard(this.dataset.uuid, '<?= h(__('UUID copied to clipboard')) ?>')"
                                                title="<?= h(__('Copy UUID')) ?>"
                                                aria-label="<?= h(__('Copy UUID')) ?>">
                                            <i class="fas fa-copy"></i>
                                        </button>
                                    </div>
                                </td>
                                <td class="text-end">
                                    <?= $this->element('genericElementsBS5/Badges/version', [
                                        'version' => (int)($dependency['minimum_version'] ?? 0),
                                    ]) ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>

    </div>
</div>
