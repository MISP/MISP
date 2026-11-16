<?php
App::uses('ValueAnalystThreadTool', 'Tools/ValueIntelligence');
/**
 * The Collaboration tab's Notes and opinions: what analysts wrote about this
 * value, drawn by the shared AnalystData/thread as on the Overview and in the
 * event view (avatar, organisation, author, age, distribution, opinion gauge,
 * replies folded under what they answer).
 *
 * What the shared thread cannot know is on a line under each entry: what it
 * hangs off (the value, an occurrence, its event, its object, a cluster),
 * since analyst data attaches to a record and never to a value, and, for an
 * opinion written on a note, that it rates the note and stays out of the
 * standing above.
 *
 * Proposals have their own card (value_analyst_proposals): they are edits
 * offered to an event, not analyst data.
 *
 * Lazily loaded from ValuesController::viewAnalystThread.
 *
 * @var array $valueIntelligence
 */
$analyst = $valueIntelligence['analyst'];
$counts = $analyst['counts'];
$items = $analyst['thread'];
$aggregate = $analyst['standing']['aggregate'] ?? null;

$canWrite = !empty($me['Role']['perm_analyst_data'])
    && $this->Acl->canAccess('analystData', 'add');
// Written on the value itself, by the SHA-256 of its text.
$hex = hash('sha256', (string)$valueIntelligence['value']);
$addUrl = function ($kind) use ($baseurl, $hex) {
    return $baseurl . '/analystData/add/' . $kind . '/' . $hex . '/AttributeValue';
};

$thread = array('Note' => array(), 'Opinion' => array(), 'Relationship' => array(), 'RelationshipInbound' => array());
foreach ($items as $item) {
    $thread[$item['kind'] === 'opinion' ? 'Opinion' : 'Note'][] = ValueAnalystThreadTool::row($item);
}

$entryContext = function ($type, $item, $nested) {
    $out = '';
    $target = $item['_target'] ?? null;
    // A reply's target is the entry it sits under, which the thread already shows.
    if ($target !== null && $target['kind'] !== 'reply') {
        $out .= $this->element('Values/View/value_analyst_target', array('target' => $target));
    }
    if ($type === 'Opinion' && ($item['_rates'] ?? 'value') !== 'value') {
        $out .= '<span class="vp-ad-uncounted" title="'
            . h(__('An opinion written on a note rates the note, so it takes no side on the value.')) . '">'
            . '<i class="fas fa-circle-info" aria-hidden="true"></i>'
            . h(($item['_target']['kind'] ?? '') === 'unresolved'
                ? __('its target does not resolve: not in the standing')
                : __('rates the note above: not in the standing'))
            . '</span>';
    }
    return $out;
};

$facts = array();
if ($counts['notes'] > 0) {
    $facts[] = '<span class="eo-fact"><i class="misp-icon misp-icon-analyst-note misp-simple"></i>'
        . h(sprintf(__n('%s note', '%s notes', $counts['notes']), number_format($counts['notes']))) . '</span>';
}
if ($counts['opinions'] > 0) {
    $facts[] = '<span class="eo-fact"><i class="misp-icon misp-icon-analyst-opinion misp-simple"></i>'
        . h(sprintf(__n('%s opinion', '%s opinions', $counts['opinions']), number_format($counts['opinions'])))
        . (empty($aggregate['n']) ? '' : ' <span class="eo-muted" title="'
            . h(__('Mean of the opinions that rate the value')) . '">'
            . h(sprintf(__('avg. %s/100'), (int)round($aggregate['mean']))) . '</span>')
        . '</span>';
}
if ($counts['replies'] > 0) {
    $facts[] = '<span class="eo-fact"><i class="fas fa-reply" aria-hidden="true"></i>'
        . h(sprintf(__n('%s reply', '%s replies', $counts['replies']), number_format($counts['replies']))) . '</span>';
}
$subtitle = empty($facts)
    ? h(__('Nothing written on this value'))
    : '<span class="eo-assessment-facts">' . implode('', $facts) . '</span>';

$addMenu = function ($buttonClass) use ($addUrl) {
    ob_start();
?>
    <div class="dropdown flex-shrink-0">
        <button type="button" class="btn btn-sm <?= $buttonClass ?> dropdown-toggle d-inline-flex align-items-center gap-1"
                data-bs-toggle="dropdown" aria-expanded="false" title="<?= h(__('Write about this value')) ?>">
            <i class="fas fa-plus"></i><span class="eo-btn-label"><?= __('Add') ?></span>
        </button>
        <ul class="dropdown-menu dropdown-menu-end">
            <li>
                <button type="button" class="dropdown-item d-flex align-items-center gap-2" onclick="openModal('<?= h($addUrl('Note')) ?>')">
                    <i class="misp-icon misp-icon-analyst-note misp-simple"></i><?= __('Note') ?>
                </button>
            </li>
            <li>
                <button type="button" class="dropdown-item d-flex align-items-center gap-2" onclick="openModal('<?= h($addUrl('Opinion')) ?>')">
                    <i class="misp-icon misp-icon-analyst-opinion misp-simple"></i><?= __('Opinion') ?>
                </button>
            </li>
        </ul>
    </div>
<?php
    return ob_get_clean();
};

$headerExtra = '';
if (!empty($items)) {
    $headerExtra .= '<div class="input-group input-group-sm eo-filter">'
        . '<span class="input-group-text border-end-0"><i class="fas fa-search text-muted small"></i></span>'
        . '<input type="search" class="form-control border-start-0 ps-0" data-vp-analyst-filter autocomplete="off"'
        . ' placeholder="' . h(__('Filter notes, opinions…')) . '" aria-label="' . h(__('Filter analyst data')) . '">'
        . '</div>';
    $headerExtra .= '<div class="vp-seg" role="group" aria-label="' . h(__('Kind')) . '">';
    foreach (array(
        'all' => sprintf(__('All %s'), $counts['items']),
        'note' => sprintf(__('Notes %s'), $counts['notes']),
        'opinion' => sprintf(__('Opinions %s'), $counts['opinions']),
    ) as $key => $label) {
        $headerExtra .= '<button type="button" class="vp-seg-btn' . ($key === 'all' ? ' active' : '') . '"'
            . ' data-vp-ad-kind="' . h($key) . '" aria-pressed="' . ($key === 'all' ? 'true' : 'false') . '">'
            . h($label) . '</button>';
    }
    $headerExtra .= '</div>';
    if ($canWrite) {
        $headerExtra .= $addMenu('btn-outline-analystData');
    }
}
?>
<div class="card shadow-sm mb-3 vp-panel eo-assessment vp-analyst-card"
     style="--vp-panel-color: var(--analystData);"
     data-vp-analyst-collab>
    <?= $this->element('Values/View/value_analyst_tab_badge', array(
        'counts' => $counts,
    )) ?>

    <?= $this->element('Values/View/value_panel_header', array(
        'panelTitle' => __('Notes and opinions'),
        'panelIcon' => 'misp-icon misp-icon-analyst-note misp-simple',
        'panelColor' => 'var(--analystData)',
        'panelSub' => $subtitle,
        'panelExtra' => $headerExtra === '' ? null : $headerExtra,
    )) ?>

    <?php if (!empty($items)): ?>
        <?php // Set from the standing card's notes badge (value-intelligence.js). ?>
        <div class="vp-ad-orgfilter d-none" data-vp-ad-orgfilter>
            <i class="fas fa-filter" aria-hidden="true"></i>
            <span data-vp-ad-orgfilter-label data-template="<?= h(__('Only %s')) ?>"></span>
            <button type="button" class="vp-ad-orgfilter-clear" data-vp-ad-orgfilter-clear>
                <i class="fas fa-xmark" aria-hidden="true"></i><?= __('Show every organisation') ?>
            </button>
        </div>
        <div class="eo-assessment-thread">
            <?= $this->element('AnalystData/thread', array(
                'analystData' => $thread,
                'objectType' => 'AttributeValue',
                'objectUuid' => $hex,
                'showEmpty' => false,
                'entryContext' => $entryContext,
            )) ?>
        </div>
        <div class="eo-empty d-none" data-vp-analyst-none><?= __('No note or opinion matches.') ?></div>
    <?php elseif ($canWrite): ?>
        <div class="eo-prompt" style="--eo-prompt:var(--analystData);">
            <div class="eo-prompt-text">
                <div class="eo-prompt-title"><?= __('Nothing written yet') ?></div>
                <p><?= __('Notes and opinions record what analysts make of this value: how far to trust it and why. They are written on the value itself.') ?></p>
            </div>
            <?= $addMenu('btn-analystData') ?>
        </div>
    <?php else: ?>
        <div class="vp-empty">
            <span class="misp-icon misp-icon-analyst-note misp-simple"></span>
            <span><?= __('Nobody has written a note or an opinion on this value.') ?></span>
        </div>
    <?php endif; ?>

    <?php if (!empty($analyst['capped'])): ?>
        <div class="eo-card-foot">
            <span class="eo-legend"><i class="fas fa-circle-info" aria-hidden="true"></i><?= h(sprintf(
                __('Assembled from the %s most recent occurrences and their events: a note on an older occurrence is not shown.'),
                number_format($valueIntelligence['occurrence_stats']['shown'] ?? 0)
            )) ?></span>
        </div>
    <?php endif; ?>
</div>
