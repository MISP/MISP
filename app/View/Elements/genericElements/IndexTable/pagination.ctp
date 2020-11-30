<?php
    $options = array(
        'update' => '.span12',
        'evalScripts' => true,
        'before' => '$(".progress").show()',
        'complete' => '$(".progress").hide()'
    );
    if (!empty($paginationOptions)) {
        $options = array_merge($options, $paginationOptions);
    }
    echo $this->Paginator->options($options);
?>
