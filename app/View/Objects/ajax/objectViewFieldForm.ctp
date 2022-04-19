<?php
if ($field === 'timestamp') {
    echo $this->Time->date($value);
} else {
    echo nl2br(h($value), false);
}
