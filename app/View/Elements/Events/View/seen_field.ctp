<?php if ($object['first_seen'] != null || $object['last_seen'] != null): ?>
    <div>
        <div><?php echo $object['first_seen'] != null ? h($object['first_seen']) : '<span style="display: block; text-align:center;">_</span>'; ?></div>
        <i style="display: block; text-align: center;" class="fas fa-arrow-down"></i>
        <div><?php echo $object['last_seen'] != null ? h($object['last_seen']) : '<span style="display: block; text-align:center;">_</span>'; ?></div>
    </div>
<?php else: ?>
    <div></div>
<?php endif; ?>
