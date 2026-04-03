<div class="bg-primary text-white py-5 shadow-sm mb-4">
    <div class="container-fluid">
        <div class="d-flex justify-content-between align-items-center">

            <h2 class="fw-semibold mb-0 d-flex align-items-center">
                <?php if (isset($currentController)): ?>
                    <?php if (isset($currentAction)): ?>
                        <span class="text-white-50 text-capitalize">
                            <?= h($currentController) ?>
                        </span>

                        <span class="mx-2 text-white-50">></span>

                        <span class="text-white text-capitalize">
                            <?= h($currentAction) ?>
                        </span>
                    <?php else: ?>
                        <span class="text-white text-capitalize">
                            <?= h($currentController) ?>
                        </span>
                    <?php endif; ?>
                <?php endif; ?>
            </h2>
            <?php if (!empty($headerActions)): ?>
                <div class="d-flex gap-2">
                    <?php foreach ($headerActions as $action): ?>
                        <?php if ($action['type'] === 'link'): ?>
                            <a href="<?= h($action['url']) ?>"
                            class="btn bg-white text-primary border-0 shadow-sm fw-semibold d-flex align-items-center gap-2">
                                <i class="fas fa-<?= h($action['icon']) ?>"></i>
                                <?= h($action['label']) ?>
                            </a>
                        <?php elseif ($action['type'] === 'post'): ?>
                            <?php
                                echo $this->Form->postLink(
                                    '<i class="fas fa-' . h($action['icon']) . '"></i> ' . h($action['label']),
                                    $action['url'],
                                    [
                                        'class' => 'btn btn-outline-light shadow-sm fw-semibold d-flex align-items-center gap-2',
                                        'escape' => false,
                                    ]
                                );
                            ?>
                        <?php elseif ($action['type'] === 'ajax'): ?>
                            <a class="btn bg-white text-primary border-0 shadow-sm fw-semibold d-flex align-items-center gap-2"
                            href="<?= h($action['url']) ?>"
                            onclick="event.preventDefault(); openModal('<?= h($action['url']) ?>');">
                                <i class="fas fa-<?= h($action['icon']) ?>"></i>
                                <?= h($action['label']) ?>
                            </a>
                        <?php endif; ?>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>

        </div>
    </div>
</div>