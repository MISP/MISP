<div class="misp-error-container">
<h2><?php echo $name; ?></h2>
<?php if (!empty($message)): ?>
<p class="error">
    <strong><?= __('Error'); ?>:</strong>
    <?= $message; ?>
</p>
<?php endif; ?>
</div>
