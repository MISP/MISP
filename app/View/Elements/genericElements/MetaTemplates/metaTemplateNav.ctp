<span>
    <?= h($metaTemplate->name) ?> 
    <?=
    $this->Bootstrap->badge([
        'variant' => !empty($metaTemplate['hasNewerVersion']) ? 'warning' : 'primary',
        'text' => sprintf('v%s', h($metaTemplate->version))
    ])
    ?>
    <?php if (!empty($metaTemplate->is_default)): ?>
        <i class="<?= $this->FontAwesome->getClass('star')?> small align-text-top" title="<?= __('Default Meta template') ?>"></i>
    <?php endif; ?>
</span>