<div class="d-flex justify-content-center">
    <div class="card shadow-sm d-inline-block w-auto">
        <div class="card-header">
            <h4 class="card-title mb-2 mt-2">
                <?php echo __('Element Deletion'); ?>
            </h4>
        </div>

        <div class="card-body">
            <?php
                echo $this->Form->create('CollectionElement', [
                    'id' => 'PromptForm',
                    'url' => $baseurl . '/collectionElements/delete2',
                    'class' => 'm-0'
                ]);
                echo $this->Form->hidden('id');
            ?>
            <?php
                if (count($idArray) > 1) {
                    $message = __('Are you sure you want to delete %s elements ?', count($idArray));
                } else {
                    $message = __('Are you sure you want to delete element #%s ?', $idArray[0]);
                }
            ?>

            <p class="mb-4"><?= h($message); ?></p>

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