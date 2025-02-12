<div class="alert alert-error" style="margin-bottom: 0">
<?php
foreach ($field['warnings'] as $key => $values) {
    $values = is_array($values) ? $values : [$values];
    foreach ($values as $value) {
        echo sprintf(
            '<b>%s</b>: <p style="margin-left:10px;">%s</p>',
            h($key),
            h($value)
        );
    }
}
?>
</div>
