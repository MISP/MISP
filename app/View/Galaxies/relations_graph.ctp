<h6>
    <a class="" href="<?= sprintf('%s/galaxies/view/%s/context:all', $baseurl, $galaxy_id) ?>">
        <i class="<?php echo $this->FontAwesome->findNamespace('arrow-left'); ?> fa-arrow-left"></i>
        <?= __('Back to galaxy') ?>
    </a>
</h6>
<?php if (empty($relations)): ?>
    <div class="alert alert-info">
        <?= __('There are no relations in this Galaxy'); ?>
    </div>
<?php else: ?>
    <div style="margin-bottom: 10px; position: relative">
        <div id="graphContainer" style="height: 70vh; border: 1px solid #ddd; "></div>
        <div id="tooltipContainer" style="max-height: 400px; width: 200px; position: absolute; top: 10px; right: 10px; border: 1px solid #999; border-radius: 3px; background-color: #f5f5f5ee; overflow: auto;"></div>
    </div>
    <?php echo $this->element('GalaxyClusters/relations_graph'); ?>
<?php endif ?>