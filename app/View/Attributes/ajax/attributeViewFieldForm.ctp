<?php
if ($field === 'value') {
    echo $this->element('Events/View/value_field', ['object' => $object['Attribute']]);
} else {
    if ($value === 'No') {
        echo '<input type="checkbox" disabled>';
    } else if ($value === 'Yes') {
        echo '<input type="checkbox" checked disabled>';
    } else {
        echo nl2br(h($value)) . '&nbsp;';
    }
}
