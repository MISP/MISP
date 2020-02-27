<?php
    $options = array(
        'update' => '.span12',
        'evalScripts' => true,
        'before' => '$(".progress").show()',
        'complete' => '$(".progress").hide()',
    );
    if (!empty($paginationBaseurl)) {
        $options['url'] = $paginationBaseurl;
    }
    echo $this->Paginator->options($options);
    echo sprintf(
        '<div class="pagination"><ul>%s%s%s</ul></div>',
        $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span')),
        $this->Paginator->numbers(array('modulus' => 20, 'separator' => '', 'tag' => 'li', 'currentClass' => 'active', 'currentTag' => 'span')),
        $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'))
    );
?>
