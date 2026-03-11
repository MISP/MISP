<div class="card shadow-sm">

    <?php if (!empty($title)): ?>
    <div class="card-header d-flex align-items-center gap-2">

        <?php if (!empty($icon)): ?>
            <i class="fas fa-<?= h($icon) ?> text-primary"></i>
        <?php endif; ?>

        <h5 class="mb-0"><?= h($title) ?></h5>

    </div>
    <?php endif; ?>

    <div class="card-body">
        <?= $content ?>
    </div>

</div>