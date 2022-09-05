<?php
$time = function ($value) {
    return $value != null ? $this->Time->time($value) : '<span style="display: block; text-align:center;">_</span>';
};

if ($object['first_seen'] != null || $object['last_seen'] != null): ?>
    <div>
        <div><?= $time($object['first_seen']) ?></div>
        <i style="display: block; text-align: center;" class="fas fa-arrow-down"></i>
        <div><?= $time($object['last_seen']) ?></div>
    </div>
<?php endif ?>
