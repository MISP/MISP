<div class="card shadow-sm mb-3">

    <?php if (!empty($title)): ?>
    <div class="card-header d-flex align-items-center fs-5">

        <?php if (!empty($icon)): ?>
        <i class="fas fa-<?= h($icon) ?> me-2 text-primary"></i>
        <?php endif; ?>

        <strong><?= h($title) ?></strong>

    </div>
    <?php endif; ?>

    <div class="card-body">

        <?= $content ?>

    </div>

</div>