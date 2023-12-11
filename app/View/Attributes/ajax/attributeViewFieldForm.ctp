<?php
if ($field === 'value') {
    echo $this->element('Events/View/value_field', ['object' => $object['Attribute']]);
} elseif ($field === 'timestamp') {
    echo $this->Time->date($value);
} elseif ($field === 'distribution') {
    if ($value == 0) {
        echo '<span class="red">' . $shortDist[$value] . '</span>';
    } else {
        echo $shortDist[$value];
    }
} else {
    echo nl2br(h($value), false);
}
