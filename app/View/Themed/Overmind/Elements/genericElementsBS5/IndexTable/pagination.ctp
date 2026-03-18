<?php
$Paginator = $this->Paginator;
$params = $Paginator->params();
$page = $params['page'] ?? 1;
$pageCount = $params['pageCount'] ?? null;

?>

<div class="d-flex justify-content-between align-items-center flex-wrap gap-3">

    <!-- COUNTER -->
    <div class="text-muted medium">
        <p class="mb-0">
            <?php echo $Paginator->counter(array(
                'format' => __('Page {:page} of {:pages}, showing {:current} records out of {:count} total, starting on record {:start}, ending on {:end}')
                ));
            ?>
        </p>
    </div>

    <?php if ($pageCount): ?>
    <nav aria-label="Pagination">
        <ul class="pagination mb-0">

            <!-- PREVIOUS -->
            <?php if ($Paginator->hasPrev()): ?>
                <li class="page-item">
                    <?php
                    echo $Paginator->prev(
                        'Previous',
                        ['class' => 'page-link'],
                        '<span class="page-link">Previous</span>',
                        ['escape' => false]
                    );
                    ?>
                </li>
            <?php else: ?>
                <li class="page-item disabled">
                    <span class="page-link">Previous</span>
                </li>
            <?php endif; ?>

            <!-- PAGE NUMBERS -->
            <?php if ($pageCount>1): ?>
                <?php for ($i = 1; $i <= $pageCount; $i++):
                    $active = ($i == $params['page']);
                ?>
                    <li class="page-item <?= $active ? 'active' : '' ?>">
                        <?php if ($active): ?>
                            <span class="page-link"><?= $i ?></span>
                        <?php else: ?>
                            <?= $Paginator->link($i, ['page' => $i], ['class' => 'page-link']) ?>
                        <?php endif; ?>
                    </li>
                <?php endfor; ?>
            <?php endif; ?>

            <!-- NEXT -->
            <?php if ($Paginator->hasNext()): ?>
                <li class="page-item">
                    <?php
                    echo $Paginator->next(
                        'Next',
                        ['class' => 'page-link'],
                        '<span class="page-link">Next</span>',
                        ['escape' => false]
                    );
                    ?>
                </li>
            <?php else: ?>
                <li class="page-item disabled">
                    <span class="page-link">Next</span>
                </li>
            <?php endif; ?>

        </ul>
    </nav>
    <?php endif; ?>

</div>