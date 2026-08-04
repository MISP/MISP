<?php
$Paginator = $this->Paginator;
$params    = $Paginator->params();
$page      = $params['page'] ?? 1;
$pageCount = $params['pageCount'] ?? null;

$maxPagesToShow = $maxPages ?? 20;
$sizeClass      = !empty($size) ? 'pagination-' . $size : '';

$half  = floor($maxPagesToShow / 2);
$start = max(1, $page - $half);
$end   = min($pageCount, $start + $maxPagesToShow - 1);

if ($end - $start + 1 < $maxPagesToShow) {
    $start = max(1, $end - $maxPagesToShow + 1);
}
?>

<nav aria-label="Pagination">
    <ul class="pagination mb-0 <?= $sizeClass ?>">

        <!-- PREVIOUS -->
        <?php if ($Paginator->hasPrev()): ?>
            <li class="page-item">
                <?= $Paginator->prev(
                    '<i class="fas fa-chevron-left"></i>',
                    ['class' => 'page-link', 'escape' => false],
                    null,
                    ['escape' => false]
                ) ?>
            </li>
        <?php else: ?>
            <li class="page-item disabled">
                <span class="page-link">
                    <i class="fas fa-chevron-left"></i>
                </span>
            </li>
        <?php endif; ?>

        <!-- PAGE NUMBERS -->
        <?php if ($pageCount > 1): ?>

            <?php if ($start > 1): ?>
                <li class="page-item">
                    <?= $Paginator->link(1, ['page' => 1], ['class' => 'page-link']) ?>
                </li>
                <?php if ($start > 2): ?>
                    <li class="page-item disabled">
                        <span class="page-link">&hellip;</span>
                    </li>
                <?php endif; ?>
            <?php endif; ?>

            <?php for ($i = $start; $i <= $end; $i++): ?>
                <li class="page-item <?= ($i == $page) ? 'active' : '' ?>">
                    <?php if ($i == $page): ?>
                        <span class="page-link"><?= $i ?></span>
                    <?php else: ?>
                        <?= $Paginator->link($i, ['page' => $i], ['class' => 'page-link']) ?>
                    <?php endif; ?>
                </li>
            <?php endfor; ?>

            <?php if ($end < $pageCount): ?>
                <?php if ($end < $pageCount - 1): ?>
                    <li class="page-item disabled">
                        <span class="page-link">&hellip;</span>
                    </li>
                <?php endif; ?>
                <li class="page-item">
                    <?= $Paginator->link($pageCount, ['page' => $pageCount], ['class' => 'page-link']) ?>
                </li>
            <?php endif; ?>

        <?php endif; ?>

        <!-- NEXT -->
        <?php if ($Paginator->hasNext()): ?>
            <li class="page-item">
                <?= $Paginator->next(
                    '<i class="fas fa-chevron-right"></i>',
                    ['class' => 'page-link', 'escape' => false],
                    null,
                    ['escape' => false]
                ) ?>
            </li>
        <?php else: ?>
            <li class="page-item disabled">
                <span class="page-link">
                    <i class="fas fa-chevron-right"></i>
                </span>
            </li>
        <?php endif; ?>

    </ul>
</nav>