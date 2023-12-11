<?php
if ($field === 'timestamp') {
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
