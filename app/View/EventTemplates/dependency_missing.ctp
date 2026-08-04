<div class="index">
    <?php if (!empty($missing)): ?>
        <p><?php echo __('Missing PHP package(s):'); ?></p>
        <ul>
        <?php foreach ($missing as $package): ?>
            <li><code><?php echo h($package); ?></code></li>
        <?php endforeach; ?>
        </ul>
    <?php endif; ?>
</div>
