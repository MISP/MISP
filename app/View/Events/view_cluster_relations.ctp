<?php if (empty($relations)): ?>
    <div class="alert alert-info">
        <?= __('There are no Cluster relationships in this Event.'); ?>
    </div>
<?php else: ?>
    <?php echo $this->element('GalaxyClusters/relations_graph'); ?>
<?php endif ?>
