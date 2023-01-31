<?php
    if (empty($value)) {
        echo sprintf(
            '<span class="bold red">%s</span>',
            __('N/A')
        );
    } else {
        echo sprintf(
            '<details>%s%s</details>',
            !empty($description) ?
            sprintf(
                '<summary style="cursor: pointer">%s</summary>',
                h($description)
            ) : '',
            sprintf(
                '<pre class="quickSelect" style="line-height: 1.44">%s</pre>',
                h($value)
            )
        );
    }
?>