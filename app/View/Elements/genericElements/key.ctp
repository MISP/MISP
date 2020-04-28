<?php if (empty($key)): ?>
    <span class="bold red"><?= __('N/A') ?></span>
<?php else: ?>
    <details>
        <?php if (!empty($description)): ?>
        <summary style="cursor: pointer"><?= h($description) ?></summary>
        <?php endif; ?>
        <pre class="quickSelect" style="line-height: 1.44"><?= h($key) ?></pre>
    </details>
<?php endif; ?>
