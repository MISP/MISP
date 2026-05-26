<?php
$Paginator = $this->Paginator;
$params    = $Paginator->params();
$pageCount = $params['pageCount'] ?? null;
?>

<div class="d-flex justify-content-between align-items-center flex-wrap gap-3">

    <!-- COUNTER -->
    <div class="text-muted medium">
        <p class="mb-0">
            <?= $Paginator->counter([
                'format' => __('Page {:page} of {:pages}, showing {:current} records out of {:count} total, starting on record {:start}, ending on {:end}')
            ]) ?>
        </p>
    </div>

    <?php if ($pageCount): ?>
        <?= $this->element(
            'genericElementsBS5/IndexTable/pagination_nav'
        ) ?>
    <?php endif; ?>

</div>