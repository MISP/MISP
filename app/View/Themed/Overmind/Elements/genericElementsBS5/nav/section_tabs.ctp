<?php

$renderNav = $renderNav ?? true;
$renderContent = $renderContent ?? true;

?>

<?php if ($renderNav): ?>
    <ul class="nav nav-tabs mb-3 fs-5" role="tablist">

        <?php foreach ($tabs as $i => $tab): ?>

            <li class="nav-item" role="presentation">
                <a class="nav-view nav-link d-flex align-items-center gap-2 <?= $i === 0 ? 'active' : '' ?>"
                    data-bs-toggle="tab"
                    href="#tab-<?= h($tab['id']) ?>"
                    role="tab"
                    aria-selected="<?= $i === 0 ? 'true' : 'false' ?>"
                    >
                    <?php if (!empty($tab['icon'])): ?>
                        <i class="fas fa-<?= h($tab['icon']) ?>"></i>
                    <?php endif; ?>
                    <span>
                        <?= h($tab['title']) ?>
                        <?php if (!empty($tab['count'])): ?>
                            <span> (<?= h($tab['count']) ?>) </span>
                        <?php endif; ?>
                    </span>
                </a>
            </li>

        <?php endforeach; ?>

    </ul>
<?php endif; ?>


<?php if ($renderContent): ?>
    <div class="tab-content">
        <?php foreach ($tabs as $i => $tab): ?>
            <div class="tab-pane fade <?= $i === 0 ? 'show active' : '' ?>"
                id="tab-<?= h($tab['id']) ?>"
                role="tabpanel">
                <?php
                    if (!empty($tab['cards'])) {
                        foreach ($tab['cards'] as $card) {
                            echo $this->element($card, ['data' => $data]);
                        }
                    }
                ?>
            </div>
        <?php endforeach; ?>
    </div>
<?php endif; ?>