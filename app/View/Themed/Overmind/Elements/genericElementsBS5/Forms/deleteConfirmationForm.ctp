<div class="d-flex justify-content-center">
    <div class="card shadow-sm d-inline-block w-auto">
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
                echo $this->Form->hidden('id');
            ?>

            <p class="mb-4"><?= h($message); ?></p>

            <div class="d-flex justify-content-between align-items-center">
                <button type="submit" class="btn btn-primary">
                    <?= __('Yes'); ?>
                </button>

                <button 
                    type="button"
                    class="btn btn-outline-secondary"
                    onclick="bootstrap.Modal.getInstance(document.getElementById('mainModal')).hide();">
                    <?= __('No'); ?>
                </button>
            </div>

            <?= $this->Form->end(); ?>
        </div>
    </div>
</div>