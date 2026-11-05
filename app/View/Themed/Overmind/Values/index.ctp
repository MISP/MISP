<?php
/**
 * `/values/index` — the way in to the Value Intelligence, laid out as the
 * other index pages are: the figures in stat cards, the box in the filter
 * bar's card, and what it answered as a count line over a table.
 *
 * The region under the bar has one occupant at a time — the invitation,
 * an answer or a worklist — so the page's script can refill it from
 * `ValuesController::triage()` without the paste above it moving. The
 * recently opened values stay under it, whatever it holds.
 *
 * @var array|null $resolution What `ValuesController::resolve()` made
 *                             of the box, or null on a plain load
 * @var array|null $triage The rows a pasted list became, or null
 * @var array $recent The values this reader last opened, newest first
 * @var array|null $inForce The Analyst Profile deciding this reader's
 *                          assessments, or null when none is
 * @var array $tiles As `ValueIntelligence::forTiles()`
 */
echo $this->element('genericElements/assetLoader', array(
    'css' => array('value-palette', 'index-filters', 'value-index', 'value-index-search'),
    'js' => array('value-index', 'value-index-search'),
));

$this->set('headerTitle', __('Values'));
$this->set('headerBreadcrumb', __('Values'));
$this->set('headerDescription', __(
    'Look up a value to see what MISP knows about it, or paste a list'
    . ' to triage it.'
));
if ($tiles['dictionary'] !== null) {
    $this->set('headerCount', (int)$tiles['dictionary']['total']);
}
?>
<div class="vi-page container-fluid">
    <?= $this->element('Values/Index/stats', array(
        'tiles' => $tiles,
    )) ?>
    <div class="ifp-card">
        <?= $this->element('Values/Index/prompt', array(
            'inForce' => $inForce,
        )) ?>
    </div>
    <div class="vi-out" data-vi-out>
<?php if ($triage !== null): ?>
        <?= $this->element('Values/Index/worklist', array(
            'triage' => $triage,
        )) ?>
<?php elseif ($resolution === null): ?>
        <?= $this->element('Values/Index/invite') ?>
<?php else: ?>
        <?= $this->element('Values/Index/answer', array(
            'resolution' => $resolution,
        )) ?>
<?php endif; ?>
    </div>
    <?php // The empty region again, for the clear control to put back. ?>
    <template data-vi-invite><?= $this->element('Values/Index/invite') ?></template>
    <?= $this->element('Values/Index/search') ?>
    <?= $this->element('Values/Index/recent', array(
        'recent' => $recent,
    )) ?>
</div>
