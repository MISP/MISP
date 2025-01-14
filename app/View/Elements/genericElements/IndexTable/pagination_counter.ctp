<?php
    echo sprintf(
        '<p>%s</p>',
        $this->Paginator->counter(
            __('Page {:page} of {:pages}, showing {:current} {:model} out of {:count} total, starting on record {:start}, ending on {:end}')
        )
    );
?>
