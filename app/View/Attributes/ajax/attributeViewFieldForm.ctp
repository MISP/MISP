<?php
if ($field === 'value') {
    echo $this->element('Events/View/value_field', ['object' => $object['Attribute']]);
} elseif ($field === 'timestamp') {
    echo $this->Time->date($value);
} else {
    echo nl2br(h($value), false);
}
