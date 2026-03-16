<?php

$leftSize = !empty($right_part) ? 9 : 12;
$rightSize = 12 - $leftSize;

?>

<div class="container-fluid mt-3">
    <h2 class="mb-3">
        <?= h($title) ?>
    </h2>
    <?= $this->element(
        'genericElementsBS5/nav/section_tabs',
        [
            'tabs' => $tabs,
            'data' => $data,
            'renderContent' => false
        ]
    ) ?>
    <div class="row">
        <!-- MAIN COLUMN -->
        <div class="col-lg-<?= $leftSize ?>">
            <?= $this->element(
                'genericElementsBS5/nav/section_tabs',
                [
                    'tabs' => $tabs,
                    'data' => $data,
                    'renderNav' => false
                ]
            ) ?>
        </div>

    <?php if (!empty($right_part)): ?>
        <!-- RIGHT COLUMN -->
        <div class="col-lg-<?= $rightSize ?>">
            <?php
                foreach ($right_part as $element) {
                    echo $this->element($element, ['data' => $data]);
                }
            ?>
        </div>
    <?php endif; ?>
    </div>
</div>