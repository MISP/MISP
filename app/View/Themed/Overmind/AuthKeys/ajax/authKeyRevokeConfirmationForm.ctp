<div class="d-flex justify-content-center">
    <div class="card shadow-sm d-inline-block w-auto">
        <div class="card-header">
            <h4 class="card-title mb-2 mt-2">
                <?= __('Revoke auth key'); ?>
            </h4>
        </div>

        <div class="card-body">
            <?php
                echo $this->Form->create('AuthKey', [
                    'id' => 'PromptForm',
                    'url' => $baseurl . '/auth_keys/revoke/' . $id,
                    'class' => 'm-0'
                ]);
            ?>

            <p class="mb-2"><?= __('Are you sure you want to revoke auth key #%s?', h($id)); ?></p>
            <p class="text-body-secondary small mb-4" style="max-width: 32rem;">
                <?= __('The key expires immediately and stops authenticating. It can be brought back later by setting a new expiration date from the edit form.'); ?>
            </p>

            <div class="d-flex justify-content-between align-items-center">
                <button type="submit" class="btn btn-warning">
                    <?= __('Revoke'); ?>
                </button>

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
