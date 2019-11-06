<?php
    echo sprintf(
        '<button onClick="%s" class="btn btn-%s">%s</button>',
        sprintf(
            "$('#%s%sForm').submit();",
            h($model),
            h(Inflector::classify($action))
        ),
        empty($type) ? 'primary' : h($type),
        empty($text) ? __('Submit') : h($text)
    );
?>
