<?php
    echo sprintf(
        '<p>%s</p>',
        $this->Paginator->counter(
            sprintf(
                __('Page %s of %s, showing %s %s out of %s total, starting on record %s, ending on %s'),
                '{{page}}',
                '{{pages}}',
                '{{current}}',
                '{{model}}',
                '{{count}}',
                '{{start}}',
                '{{end}}'
            )
        )
    );
?>
