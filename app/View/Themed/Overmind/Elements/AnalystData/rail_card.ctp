<?php
/*
 * The Analyst data card of a detail page's rail: an "Add a note" launcher
 * with opinion and relationship beside it, and the thread attached to the
 * record under it (AnalystData/thread, limited to its latest entries).
 *
 * Params:
 *   $objectType : the record's type (GalaxyCluster, EventReport, Note, …)
 *   $objectUuid : the record's uuid
 *   $showThread : draw the thread (default true); a page whose main column
 *                 already shows it passes false and keeps the launcher only
 */
App::uses('ClassRegistry', 'Utility');

$objectType = $objectType ?? '';
$objectUuid = $objectUuid ?? '';
$showThread = !isset($showThread) || $showThread;
if ($objectType === '' || $objectUuid === '') {
    return;
}

$canAdd = !empty($me['Role']['perm_analyst_data']);
$thread = $showThread
    ? ClassRegistry::init('Note')->fetchThreadForObject($me, $objectType, $objectUuid)
    : ['Note' => [], 'Opinion' => [], 'Relationship' => [], 'RelationshipInbound' => []];
$isEmpty = empty($thread['Note']) && empty($thread['Opinion'])
    && empty($thread['Relationship']) && empty($thread['RelationshipInbound']);

if ($isEmpty && !$canAdd) {
    return;
}

$countTree = function (array $items) use (&$countTree) {
    $n = 0;
    foreach ($items as $item) {
        $n += 1 + $countTree($item['Note'] ?? []) + $countTree($item['Opinion'] ?? []);
    }
    return $n;
};
$total = $countTree($thread['Note']) + $countTree($thread['Opinion'])
    + $countTree($thread['Relationship']) + count($thread['RelationshipInbound']);

$addUrl = function ($type) use ($baseurl, $objectType, $objectUuid) {
    return $baseurl . '/analystData/add/' . $type . '/' . rawurlencode($objectUuid) . '/' . $objectType;
};
?>
<section class="card shadow-sm mb-3 adr-card<?= $isEmpty ? ' adr-card-empty' : '' ?>" aria-label="<?= __('Analyst data') ?>">
    <?php if ($canAdd): ?>
        <div class="adr-composer">
            <button type="button" class="adr-field" data-adr-open="<?= h($addUrl('Note')) ?>">
                <i class="misp-icon misp-icon-analyst-note misp-simple adr-field-ico" aria-hidden="true"></i>
                <span class="adr-field-ph"><?= __('Add a note…') ?></span>
            </button>
            <button type="button" class="adr-side adr-side-opinion" title="<?= __('Add an opinion') ?>" aria-label="<?= __('Add an opinion') ?>" data-adr-open="<?= h($addUrl('Opinion')) ?>">
                <i class="misp-icon misp-icon-analyst-opinion misp-simple" aria-hidden="true"></i>
            </button>
            <button type="button" class="adr-side adr-side-rel" title="<?= __('Add a relationship') ?>" aria-label="<?= __('Add a relationship') ?>" data-adr-open="<?= h($addUrl('Relationship')) ?>">
                <i class="fas fa-diagram-project" aria-hidden="true"></i>
            </button>
        </div>
    <?php else: ?>
        <div class="adr-head">
            <span class="adr-head-tile" aria-hidden="true"><i class="fas fa-comment-dots"></i></span>
            <span class="adr-head-title"><?= __('Analyst data') ?></span>
            <span class="adr-head-count"><?= (int)$total ?></span>
        </div>
    <?php endif; ?>

    <?php if (!$isEmpty): ?>
        <?= $this->element('AnalystData/thread', [
            'objectType' => $objectType,
            'objectUuid' => $objectUuid,
            'analystData' => $thread,
            'limit' => true,
            'showEmpty' => false,
        ]) ?>
    <?php endif; ?>
</section>
