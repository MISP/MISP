<div class="d-flex justify-content-center">
    <div class="card shadow-sm d-inline-block w-auto">
        <?php
            echo $this->Form->create('Event', [
                'id' => 'PromptForm', 
                'url' => $baseurl . '/events/' . $type . '/' . $id,
                'class' => 'm-0'
            ]);
            if ($type === 'unpublish') {
                $title = __('Unpublish Event');
                $buttonTitle = __('Unpublish');
            } else {
                $extraTitle = $type === 'publish' ? ' (no email)' : '';
                $title = __('Publish Event%s', $extraTitle);
                $buttonTitle = __('Publish');
            }
        ?>
        <div class="card-header">
            <h4 class="card-title mb-2 mt-2">
                <?php echo h($title); ?>
            </h4>
        </div>

        <div class="card-body">
            <?php
                if ($type === 'alert') {
                    $message =  __('Are you sure this event is complete and everyone should be informed?');
                } else if ($type === 'unpublish') {
                    $message = __('Are you sure you wish to unpublish the event?');
                } else if ($type === 'publishSightings') {
                    $message =  __('Are you sure you wish publish and synchronise all sightings attached to this event?');
                } else {
                    $message = __('Publish but do NOT send alert email! Only for minor changes!');
                }
            ?>
            <p class="mb-4"><?= h($message); ?></p>

            <?php if (!empty($servers)): ?>
                <div class="card mb-3">
                    <div class="card-header bg-light fw-bold">
                        <i class="bi bi-server me-2"></i><?= __('Servers') ?>
                    </div>
                    <ul class="list-group list-group-flush">
                        <?php foreach ($servers as $serverName => $reason): ?>
                        <li class="list-group-item d-flex justify-content-between align-items-center">
                            <span><?= h($serverName) ?></span>
                            <?php if ($reason === true): ?>
                                <span class="badge bg-success-subtle text-success border border-success-subtle rounded-pill">
                                    <i class="bi bi-check-circle me-1"></i><?= __('Event will be pushed') ?>
                                </span>
                            <?php else: ?>
                                <span class="text-muted small italic"><?= h($reason) ?></span>
                            <?php endif; ?>
                        </li>
                        <?php endforeach; ?>
                    </ul>
                </div>
            <?php endif; ?>

            <div class="d-flex justify-content-between align-items-center">
                <button 
                    type="submit"
                    aria-label="<?= $buttonTitle ?>"
                    title="<?= $buttonTitle ?>"
                    id="PromptYesButton"
                    class="btn btn-primary">
                    <?php echo __('Yes');?>
                </button>

                <button 
                    type="button"
                    class="btn btn-outline-secondary"
                    title="<?= __('Cancel');?>"
                    aria-label="<?= __('Cancel');?>"
                    id="PromptNoButton"
                    onclick="bootstrap.Modal.getInstance(document.getElementById('mainModal')).hide();">
                    <?php echo __('No');?>
                </button>
            </div>

            <?= $this->Form->end(); ?>
        </div>
    </div>
</div>