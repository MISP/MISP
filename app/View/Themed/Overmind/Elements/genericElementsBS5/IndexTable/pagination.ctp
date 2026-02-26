<?php
$data = $scaffold_data['data'];
$Paginator = $this->Paginator;
?>

<div class="d-flex justify-content-between align-items-center flex-wrap gap-3">

    <div class="text-muted medium">
        <p class="mb-0">
            <?php echo $Paginator->counter(array(
                'format' => __('Page {:page} of {:pages}, showing {:current} records out of {:count} total, starting on record {:start}, ending on {:end}')
                ));
            ?>
        </p>
    </div>

    <nav aria-label="pagination">
        <ul class="pagination mb-0">
            <!-- PREV -->
            <li class="page-item <?= !$this->Paginator->hasPrev() ? 'disabled' : ''; ?>">
                <?= $this->Paginator->prev('Previous', ['class' => 'page-link']) ?>
            </li>

            <!-- NUMBERS -->
            <?php if ($this->Paginator->params()['pageCount'] > 1): ?>
                <?= $this->Paginator->numbers([
                    'tag' => 'li',
                    'separator' => '',
                    'class' => 'page-item',
                    'currentClass' => 'active',
                    'currentTag' => 'span',
                    'currentLinkClass' => 'page-link'
                ]); ?>
            <?php endif; ?>

            <!-- NEXT -->
            <li class="page-item <?= !$this->Paginator->hasNext() ? 'disabled' : ''; ?>">
                <?= $this->Paginator->next('Next', ['class' => 'page-link']) ?>
            </li>
        </ul>
    </nav>

</div>
