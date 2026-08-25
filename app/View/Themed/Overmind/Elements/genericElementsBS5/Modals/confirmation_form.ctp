<?php
/*
 * confirmationForm.ctp — generic "are you sure?" modal body for an action that
 * needs a real POST (so the form is server-rendered and carries a valid token).
 *
 * Expected:
 *   $title        => modal heading
 *   $model        => model name for Form->create
 *   $url          => POST target
 *   $message      => the question
 * Optional:
 *   $hiddenField  => name of the hidden field carrying the payload (default 'id');
 *                    false when the payload already travels in the POST URL
 *   $submitLabel  => submit button label (default Yes)
 *   $submitClass  => submit button class (default btn btn-primary)
 *   $submitIcon   => Font Awesome icon name without the "fa-" prefix
 *   $warning      => extra cautionary line rendered above the buttons
 *   $canProceed   => false to drop the submit button, leaving only a way out
 *                    (nothing in the selection is actionable)
 */
$hiddenField = $hiddenField ?? 'id';
$submitLabel = $submitLabel ?? __('Yes');
$submitClass = $submitClass ?? 'btn btn-primary';
$submitIcon = $submitIcon ?? null;
$canProceed = $canProceed ?? true;
?>

<div class="d-flex justify-content-center">
    <div class="card shadow-sm d-inline-block w-auto" style="max-width: 32rem;">
        <div class="card-header">
            <h4 class="card-title mb-2 mt-2">
                <?= h($title); ?>
            </h4>
        </div>

        <div class="card-body">
            <?php
                echo $this->Form->create($model, [
                    'id' => 'PromptForm',
                    'url' => $url,
                    'class' => 'm-0'
                ]);
                if ($hiddenField !== false) {
                    echo $this->Form->hidden($hiddenField);
                }
            ?>

            <p class="mb-3"><?= h($message); ?></p>

            <?php if (!empty($warning)): ?>
                <div class="alert alert-warning d-flex mb-3" role="alert">
                    <i class="fas fa-triangle-exclamation me-2 mt-1"></i>
                    <div><?= h($warning) ?></div>
                </div>
            <?php endif; ?>

            <div class="d-flex justify-content-between align-items-center">
                <?php if ($canProceed): ?>
                    <button type="submit" class="<?= h($submitClass) ?>">
                        <?php if ($submitIcon): ?><i class="fas fa-<?= h($submitIcon) ?> me-1"></i><?php endif; ?>
                        <?= h($submitLabel); ?>
                    </button>
                <?php endif; ?>

                <button
                    type="button"
                    class="btn btn-outline-secondary<?= $canProceed ? '' : ' ms-auto' ?>"
                    onclick="bootstrap.Modal.getInstance(document.getElementById('mainModal')).hide();">
                    <?= $canProceed ? __('Cancel') : __('Close'); ?>
                </button>
            </div>

            <?= $this->Form->end(); ?>
        </div>
    </div>
</div>
