<?php
if ($value === 'No') {
    echo '<input type="checkbox" disabled></input>';
} else if ($value === 'Yes') {
    echo '<input type="checkbox" checked disabled></input>';
} else {
    echo nl2br(h($value)) . '&nbsp;';
}
