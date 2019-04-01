<?php
    echo sprintf(
        '<p>%s</p>',
        $paginator->counter(array(
        'format' => __('Page {:page} of {:pages}, showing {:current} records out of {:count} total, starting on record {:start}, ending on {:end}')
        ))
    );
?>
