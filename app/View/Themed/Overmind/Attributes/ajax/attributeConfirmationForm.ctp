<div class="d-flex justify-content-center">
    <div class="card shadow-sm d-inline-block w-auto">
        <div class="card-header">
            <h4 class="card-title mb-2 mt-2">
                <?php echo __('Attribute Deletion'); ?>
            </h4>
        </div>

        <div class="card-body">
            <?php
                echo $this->Form->create('Attribute', [
                    'id' => 'PromptForm',
                    'url' => $baseurl . '/attributes/delete/' . $id . ($hard ? '/true' : ''),
                    'class' => 'm-0'
                ]);
                echo $this->Form->hidden('id');
                if ($hard) $hard = '/true';
            ?>
            <?php
                if (count($idArray) > 1) {
                    $hard_message = __('Are you sure you want to hard-delete Attribute #%s? The Attribute will be permanently deleted and unrecoverable. Also, this will prevent the deletion to be propagated to other instances.',  count($idArray));
                    $soft_message = __('Are you sure you want to soft-delete Attribute #%s? The Attribute will only be soft deleted, meaning that it is not completely purged. Click on Include deleted attributes and delete the soft deleted attribute if you want to permanently remove it.',  count($idArray));
                } else {
                    $hard_message = __('Are you sure you want to hard-delete Attribute #%s? The Attribute will be permanently deleted and unrecoverable. Also, this will prevent the deletion to be propagated to other instances.', h($id));
                    $soft_message = __('Are you sure you want to soft-delete Attribute #%s? The Attribute will only be soft deleted, meaning that it is not completely purged. Click on Include deleted attributes and delete the soft deleted attribute if you want to permanently remove it.', h($id));
                }
            ?>

            <p class="mb-4"><?php echo $hard ? $hard_message : $soft_message; ?></p>

            <div class="d-flex justify-content-between align-items-center">
                <button 
                    type="submit"
                    class="btn btn-primary"
                    title="<?php echo __('Accept');?>"
                    aria-label="<?php echo __('Accept');?>"
                    id="PromptYesButton">
                    <?php echo __('Yes');?>
                </button>

                <button 
                    type="button"
                    class="btn btn-outline-secondary"
                    title="<?php echo __('Cancel');?>"
                    aria-label="<?php echo __('Cancel');?>"
                    id="PromptNoButton"
                    onclick="bootstrap.Modal.getInstance(document.getElementById('mainModal')).hide();">
                    <?php echo __('No');?>
                </button>
            </div>

            <?= $this->Form->end(); ?>
        </div>
    </div>
</div>


