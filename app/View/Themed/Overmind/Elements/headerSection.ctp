<div class="bg-primary text-white py-5 shadow-sm mb-4">
    <div class="container-fluid">
        <div class="d-flex justify-content-between align-items-center">

            <h2 class="fw-semibold mb-0">
                <?= h($pageTitle) ?>
            </h2>

            <?php if (!empty($headerActions)): ?>
                <div class="d-flex gap-2">
                    <?php foreach ($headerActions as $action): ?>
                        <a href="<?= h($action['url']) ?>"
                           class="btn bg-white text-primary border-0 shadow-sm fw-semibold d-flex align-items-center gap-2">
                            <i class="fas fa-<?= h($action['icon']) ?>"></i>
                            <?= h($action['label']) ?>
                        </a>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>

        </div>
    </div>
</div>