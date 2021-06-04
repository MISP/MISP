<div class="events">
    <div id="eventIndexTable">
        <h2><?php echo __('Events');?></h2>
        <div class="pagination">
            <ul>
            <?php
                $this->Paginator->options(array(
                    'data-paginator' => '#eventIndexTable',
                ));
                $pagination = $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
                $pagination .= $this->Paginator->numbers(array('modulus' => 20, 'separator' => '', 'tag' => 'li', 'currentClass' => 'active', 'currentTag' => 'span'));
                $pagination .= $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
                echo $pagination;
            ?>
            </ul>
        </div>
        <?= $this->element('Events/eventIndexTable'); ?>
        <p>
        <?php
        echo $this->Paginator->counter(array(
        'format' => __('Page {:page} of {:pages}, showing {:current} records out of {:count} total, starting on record {:start}, ending on {:end}')
        ));
        ?>
        </p>
        <div class="pagination">
            <ul>
            <?= $pagination ?>
            </ul>
        </div>
    </div>
</div>
