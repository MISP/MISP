<?php
    $paginator->options(array(
        'update' => '.span12',
        'evalScripts' => true,
        'before' => '$(".progress").show()',
        'complete' => '$(".progress").hide()',
    ));
    sprintf(
        '<div class="pagination"><ul>%s%s%s</ul></div>',
        $paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span')),
        $paginator->numbers(array('modulus' => 20, 'separator' => '', 'tag' => 'li', 'currentClass' => 'active', 'currentTag' => 'span')),
        $paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'))
    );
?>
