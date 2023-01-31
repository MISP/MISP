<?php

use Cake\Routing\Router;

$seed = 's-' . mt_rand();
$variant = empty($notification['variant']) ? 'primary' : $notification['variant'];
?>
<a
    class="notification-item dropdown-item px-2 btn"
    <?php if (empty($notification['_useModal'])): ?>
        href="<?= Router::url($notification['router']) ?>"
    <?php else: ?>
        onclick="UI.submissionModal('<?= Router::url($notification['router']) ?>', {closeOnSuccess: false})"
    <?php endif; ?>
    title="<?= sprintf('%s:&#010; %s', $this->ValueGetter->get($notification['text']), $this->ValueGetter->get($notification['details'])) ?>"
>
    <div class="d-flex align-items-center">
        <?php if (!empty($notification['icon'])) : ?>
            <span class="notification-icon rounded-circle <?= "btn-{$variant} me-2" ?> position-relative">
                <?= $this->Bootstrap->icon($notification['icon'], ['class' => ['fa-fw', 'position-absolute top-50 start-50 translate-middle']]) ?>
            </span>
        <?php endif; ?>
        <span class="notification-text-container">
            <div class="d-flex justify-content-between align-items-center gap-2">
                <span class="notification-title text-truncate"><?= $this->ValueGetter->get($notification['text']) ?></span>
                <?php if (!empty($notification['datetime'])) : ?>
                    <small id="<?= $seed ?>" class="notification-date text-muted fw-light"><?= h($notification['datetime']->format('Y-m-d\TH:i:s')) ?></small>
                <?php endif; ?>
            </div>
            <?php if (!empty($notification['details'])) : ?>
                <small class="notification-details text-muted text-wrap lh-1 text-truncate">
                    <?= $this->ValueGetter->get($notification['details']) ?>
                </small>
            <?php endif; ?>
        </span>
    </div>
</a>
<script>
    document.getElementById('<?= $seed ?>').innerHTML = moment(document.getElementById('<?= $seed ?>').innerHTML).fromNow();
</script>