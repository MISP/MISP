<?php
$count = count($idArray);
$enable = !empty($state);
$verb = $enable ? __('enable') : __('disable');
$Verb = $enable ? __('Enable') : __('Disable');
$icon = $enable ? 'fa-play' : 'fa-pause';
$color = $enable ? 'success' : 'secondary';
$message = $count > 1
    ? __('%s decaying models will be %s.', $count, $enable ? __('enabled') : __('disabled'))
    : __('Decaying model #%s will be %s.', h($idArray[0]), $enable ? __('enabled') : __('disabled'));
?>
<div class="text-center px-3 py-4">

    <div class="mb-3">
        <span class="d-inline-flex align-items-center justify-content-center rounded-circle bg-<?= $color ?>-subtle"
              style="width:64px; height:64px;">
            <i class="fas <?= $icon ?> fa-2x text-<?= $color ?>-emphasis"></i>
        </span>
    </div>

    <h5 class="fw-bold mb-1">
        <?= $count > 1 ? __('%s %s decaying models?', $Verb, $count) : __('%s this decaying model?', $Verb) ?>
    </h5>
    <p class="text-muted small mb-4"><?= $message ?></p>

    <?php
        echo $this->Form->create('DecayingModel', [
            'id' => 'PromptForm',
            'url' => $url,
            'class' => 'm-0',
        ]);
    ?>
        <div class="d-flex justify-content-center gap-2">
            <button type="button" class="btn btn-outline-secondary"
                    onclick="bootstrap.Modal.getInstance(document.getElementById('mainModal')).hide();">
                <?= __('Cancel') ?>
            </button>
            <button type="submit" class="btn btn-<?= $enable ? 'success' : 'secondary' ?>">
                <i class="fas <?= $icon ?> me-1"></i><?= $Verb ?>
            </button>
        </div>
    <?= $this->Form->end(); ?>

</div>
