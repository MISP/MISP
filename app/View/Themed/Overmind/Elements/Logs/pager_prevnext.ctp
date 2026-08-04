<?php
/*
 * Compact "‹ Page N ›" pager for the log filter bars.
 */
$P    = $this->Paginator;
$page = $P->params()['page'] ?? 1;
?>
<nav aria-label="Pagination">
    <ul class="pagination pagination-sm mb-0">

        <?php if ($P->hasPrev()): ?>
            <li class="page-item">
                <?= $P->prev('<i class="fas fa-chevron-left"></i>',
                    ['class' => 'page-link', 'escape' => false], null, ['escape' => false]) ?>
            </li>
        <?php else: ?>
            <li class="page-item disabled">
                <span class="page-link"><i class="fas fa-chevron-left"></i></span>
            </li>
        <?php endif; ?>

        <li class="page-item disabled">
            <span class="page-link"><?= __('Page %s', (int)$page) ?></span>
        </li>

        <?php if ($P->hasNext()): ?>
            <li class="page-item">
                <?= $P->next('<i class="fas fa-chevron-right"></i>',
                    ['class' => 'page-link', 'escape' => false], null, ['escape' => false]) ?>
            </li>
        <?php else: ?>
            <li class="page-item disabled">
                <span class="page-link"><i class="fas fa-chevron-right"></i></span>
            </li>
        <?php endif; ?>

    </ul>
</nav>
