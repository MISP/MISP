<div class="index">
    <h2><?php echo __('Event templating unavailable'); ?></h2>
    <div class="alert alert-error">
        <?php echo h($message); ?>
    </div>
    <?php if (!empty($missing)): ?>
        <p><?php echo __('Missing PHP package(s):'); ?></p>
        <ul>
        <?php foreach ($missing as $package): ?>
            <li><code><?php echo h($package); ?></code></li>
        <?php endforeach; ?>
        </ul>
    <?php endif; ?>
</div>
