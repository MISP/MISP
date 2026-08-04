<h6>
    <a class="" href="<?= sprintf('%s/galaxies/view/%s/context:all', $baseurl, $galaxy_id) ?>">
        <i class="<?php echo $this->FontAwesome->findNamespace('arrow-left'); ?> fa-arrow-left"></i>
        <?= __('Back to galaxy') ?>
    </a>
</h6>
<h2><?= sprintf(__('%s galaxy cluster relationships'), h($galaxy['Galaxy']['name'])) ?></h2>
<?php if (empty($relations)): ?>
    <div class="alert alert-info">
        <?= __('There are no relations in this Galaxy'); ?>
    </div>
<?php else: ?>
    <?php echo $this->element('GalaxyClusters/relations_graph'); ?>
<?php endif ?>
