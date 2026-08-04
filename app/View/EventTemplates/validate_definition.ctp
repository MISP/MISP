<?php
    $valid = !empty($result['valid']);
    $errors = isset($result['errors']) ? $result['errors'] : array();
?>
<div class="index">
    <h2><?php echo __('Validate Event Template Definition'); ?></h2>
    <?php if ($valid): ?>
        <div class="alert alert-success">
            <?php echo __('Definition is valid.'); ?>
        </div>
    <?php else: ?>
        <div class="alert alert-error">
            <?php echo __('Definition has errors:'); ?>
        </div>
        <ul>
        <?php foreach ($errors as $err): ?>
            <li><?php echo h($err); ?></li>
        <?php endforeach; ?>
        </ul>
    <?php endif; ?>
    <p class="help-block">
        <?php echo __('This endpoint is typically consumed by the visual builder (Phase 2). REST callers receive <code>{"valid": bool, "errors": []}</code>.'); ?>
    </p>
</div>
