<?php
    $accordionId = Cake\Utility\Security::randomString(8);
?>
<div class="accordion <?= !empty($class) ? $class : '' ?>" id="accordion-<?= $accordionId ?>">
    <?php foreach ($children as $child): ?>
        <?php $childId = Cake\Utility\Security::randomString(8); ?>
        <div class="accordion-item">
            <h2 class="accordion-header" id="heading-<?= $childId ?>">
                <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapse-<?= $childId ?>" aria-expanded="false" aria-controls="collapse-<?= $childId ?>">
                <?= h($child['title']) ?>
                </button>
            </h2>
            <div id="collapse-<?= $childId ?>" class="accordion-collapse collapse" aria-labelledby="heading-<?= $accordionId ?>" data-bs-parent="#accordion-<?= $accordionId ?>">
                <div class="accordion-body">
                    <?= $child['body'] ?>
                </div>
            </div>
        </div>
    <?php endforeach; ?>
</div>