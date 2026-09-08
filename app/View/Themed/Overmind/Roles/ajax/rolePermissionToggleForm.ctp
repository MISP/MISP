<?php
/**
 * Modal to grant/deny a single permission flag on a role.
 *
 * Provided by the controller:
 *   $role     => the Role array (id, name, ...)
 *   $perm     => the permission flag key (e.g. 'perm_sync')
 *   $permFlag => the flag metadata (['text' => ..., 'title' => ...])
 *   $granted  => bool, whether the flag is currently enabled
 */
$toggleUrl = $baseurl . '/admin/roles/togglePermission/' . h($role['id']) . '/' . h($perm);
?>
<div class="d-flex justify-content-center">
    <div class="card shadow-sm d-inline-block w-auto" style="max-width: 32rem;">
        <div class="card-header">
            <h4 class="card-title mb-2 mt-2">
                <i class="fas fa-key text-primary me-2"></i>
                <?= h($permFlag['text']) ?>
            </h4>
        </div>

        <div class="card-body">
            <?php if (!empty($permFlag['title'])): ?>
                <p class="text-body-secondary mb-3"><?= h($permFlag['title']) ?></p>
            <?php endif; ?>

            <p class="mb-4 d-flex align-items-center gap-2">
                <?= __('Current status for role <strong>%s</strong>:', h($role['name'])) ?>
                <?php if ($granted): ?>
                    <span class="badge bg-success"><?= __('Granted') ?></span>
                <?php else: ?>
                    <span class="badge bg-secondary"><?= __('Denied') ?></span>
                <?php endif; ?>
            </p>

            <?php
                echo $this->Form->create('Role', [
                    'id' => 'PromptForm',
                    'url' => $toggleUrl,
                    'class' => 'm-0'
                ]);
            ?>

            <div class="d-flex justify-content-between align-items-center">
                <?php if ($granted): ?>
                    <button type="submit" class="btn btn-danger">
                        <i class="fas fa-ban me-1"></i><?= __('Deny permission') ?>
                    </button>
                <?php else: ?>
                    <button type="submit" class="btn btn-success">
                        <i class="fas fa-check me-1"></i><?= __('Grant permission') ?>
                    </button>
                <?php endif; ?>

                <button
                    type="button"
                    class="btn btn-outline-secondary"
                    onclick="bootstrap.Modal.getInstance(document.getElementById('mainModal')).hide();">
                    <?= __('Cancel'); ?>
                </button>
            </div>

            <?= $this->Form->end(); ?>
        </div>
    </div>
</div>
