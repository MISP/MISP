<?php
/**
 * Event-level galaxy cluster listing for view2.
 * Reuses the existing galaxyQuickViewNew element for
 * consistent look, feel, and edit controls.
 *
 * @var array $galaxies Galaxy records with GalaxyCluster
 * @var int   $eventId
 */
?>
<div id="galaxies_div">
    <span class="title-section"><?= __('Galaxies') ?></span>
    <?= $this->element('galaxyQuickViewNew', [
        'data' => $galaxies,
        'event' => $event,
        'target_id' => $eventId,
        'target_type' => 'event',
    ]) ?>
</div>
