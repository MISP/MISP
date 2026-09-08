<?php
$count = count($idArray);
$message = $count > 1
    ? __('You are about to permanently delete %s decaying models. This cannot be undone.', $count)
    : __('You are about to permanently delete decaying model #%s. This cannot be undone.', h($idArray[0]));
?>
<div class="text-center px-3 py-4">

    <div class="mb-3">
        <span class="d-inline-flex align-items-center justify-content-center rounded-circle bg-danger-subtle"
              style="width:64px; height:64px;">
            <i class="fas fa-trash-can fa-2x text-danger"></i>
        </span>
    </div>

    <h5 class="fw-bold mb-1">
        <?= $count > 1 ? __('Delete %s decaying models?', $count) : __('Delete this decaying model?') ?>
    </h5>
    <p class="text-muted small mb-4"><?= $message ?></p>

    <?php
        echo $this->Form->create('DecayingModel', [
            'id' => 'PromptForm',
            'url' => $baseurl . '/decayingModel/deleteSelection',
            'class' => 'm-0',
        ]);
        echo $this->Form->hidden('id');
    ?>
        <div class="d-flex justify-content-center gap-2">
            <button type="button" class="btn btn-outline-secondary"
                    onclick="bootstrap.Modal.getInstance(document.getElementById('mainModal')).hide();">
                <?= __('Cancel') ?>
            </button>
            <button type="submit" class="btn btn-danger">
                <i class="fas fa-trash-can me-1"></i><?= __('Delete') ?>
            </button>
        </div>
    <?= $this->Form->end(); ?>

</div>
