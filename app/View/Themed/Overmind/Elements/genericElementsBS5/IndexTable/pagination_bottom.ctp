<?php
/**
 * The row under a picker bar's results: where this page sits in the list,
 * and the pager.
 *
 * @var int $rows how many rows the page shows
 * @var string $class extra classes for the row
 */
$paging = $this->Paginator->params();
$first = ((int)($paging['page'] ?? 1) - 1) * (int)($paging['limit'] ?? 0) + 1;
?>
<div class="ifp-bottom<?= empty($class) ? '' : ' ' . h($class) ?>" data-tour="index-pagination">
    <span class="ifp-count"><?php
        // An index paged by "is there a next one" has no total, last page included.
        $openEnded = (!empty($paging['nextPage']) || !isset($paging['count']))
            && (int)($paging['pageCount'] ?? 0) <= (int)($paging['page'] ?? 1);
        if (!empty($paging['current']) && (int)$paging['current'] === $rows && $openEnded) {
            echo sprintf(
                h(__('Showing %s–%s')),
                h(number_format($first)),
                h(number_format($first + $rows - 1))
            );
        } elseif (!empty($paging['current']) && (int)$paging['current'] === $rows) {
            echo sprintf(
                h(__('Showing %s–%s of %s')),
                h(number_format($first)),
                h(number_format($first + (int)$paging['current'] - 1)),
                '<b>' . h(number_format((int)$paging['count'])) . '</b>'
            );
        }
    ?></span>
    <?= $this->element(
        'genericElementsBS5/IndexTable/pagination_nav',
        ['maxPages' => 5, 'size' => 'sm']
    ) ?>
</div>
