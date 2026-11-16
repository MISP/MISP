<?php
App::uses('ValueUrlTool', 'Tools/ValueIntelligence');
App::uses('ValueAnalystThreadTool', 'Tools/ValueIntelligence');
/**
 * The Relationships tab's Asserted by analysts: relationships somebody wrote
 * down on purpose, on this value, one of its occurrences, its event or its
 * object. Drawn by the shared AnalystData/thread as the Collaboration tab's
 * Notes and opinions are (avatar, organisation, author, age, distribution,
 * the sentence, the notes and opinions written on it folded under it).
 *
 * Under each claim, what the thread cannot know: which record of this value
 * it was written on (`value_analyst_target`) and what its far end is.
 * Nothing here is ranked or cut: the only thing that removes a claim is a
 * distribution the reader is outside of.
 *
 * Lazily loaded from ValuesController::viewRelationAsserted.
 *
 * @var array $valueIntelligence
 */
$asserted = $valueIntelligence['relationships']['asserted'];
$claims = $asserted['claims'];

$canWrite = !empty($me['Role']['perm_analyst_data'])
    && $this->Acl->canAccess('analystData', 'add');
// Written on the value itself, by the SHA-256 of its text.
$hex = hash('sha256', (string)$valueIntelligence['value']);
$addUrl = $baseurl . '/analystData/add/Relationship/' . $hex . '/AttributeValue';

// This value's end of the claim, in the sentence.
$selfWords = array(
    'event' => __('its event'),
    'object' => __('its object'),
);
// What the shared thread names a resolved end by.
$labelKeys = array(
    'Event' => 'info',
    'Attribute' => 'value',
    'Object' => 'name',
    'GalaxyCluster' => 'value',
    'AttributeValue' => 'value',
);

$links = array('Relationship' => array(), 'RelationshipInbound' => array());
$outbound = 0;
$replies = 0;
foreach ($claims as $claim) {
    $target = $claim['target'];
    $record = array();
    if (!empty($target['resolved'])) {
        $record = array(
            'id' => $target['id'] ?? null,
            $labelKeys[$target['kind']] ?? 'name' => $target['label'],
        );
        if ($target['kind'] === 'AttributeValue') {
            $record['_url'] = $baseurl . '/values/view/' . ValueUrlTool::address($target['label']);
        }
    }
    $isOut = $claim['direction'] === 'outbound';
    $outbound += $isOut ? 1 : 0;
    $row = array(
        'id' => $claim['id'],
        'uuid' => $claim['uuid'],
        'created' => $claim['created'],
        'distribution' => $claim['distribution'],
        'authors' => $claim['authors'] === '' ? __('unattributed') : $claim['authors'],
        'Orgc' => array('name' => $claim['org']),
        '_canEdit' => $claim['can_edit'],
        'relationship_type' => $claim['relationship_type'],
        '_self' => $selfWords[$claim['attached_to']['kind']] ?? __('this value'),
        '_target' => $claim['attached_to'],
        '_claim' => $claim,
        'related_object' => empty($record) ? array() : array($target['kind'] => $record),
        $isOut ? 'related_object_type' : 'object_type' => $target['kind'],
        $isOut ? 'related_object_uuid' : 'object_uuid' => $target['uuid'],
        'Note' => array(),
        'Opinion' => array(),
    );
    foreach ($claim['replies'] ?? array() as $reply) {
        $row[$reply['kind'] === 'opinion' ? 'Opinion' : 'Note'][] = ValueAnalystThreadTool::row($reply);
        $replies++;
    }
    $links[$isOut ? 'Relationship' : 'RelationshipInbound'][] = $row;
}
$inbound = count($claims) - $outbound;

/*
 * Under a claim: the record of this value it was written on, then where
 * its far end lives and who made it. A reply's target is the claim above.
 */
$entryContext = function ($type, $item, $nested) use ($baseurl) {
    if ($nested || !isset($item['_claim'])) {
        return '';
    }
    $out = $this->element('Values/View/value_analyst_target', array('target' => $item['_target']));
    $target = $item['_claim']['target'];
    if (empty($target['resolved'])) {
        return $out . '<span class="vp-ad-uncounted" title="'
            . h(__('Not held on this instance, or not visible to you: the claim is shown by the UUID it names.')) . '">'
            . '<i class="fas fa-circle-question" aria-hidden="true"></i>' . h(__('its other end does not resolve')) . '</span>';
    }
    $facts = array();
    if (!empty($target['event'])) {
        $facts[] = $this->element('Attributes/event_ref', array('event' => $target['event']));
    }
    foreach ($target['facts'] ?? array() as $fact) {
        $facts[] = h($fact);
    }
    if (!empty($target['org']['name'])) {
        $facts[] = $this->element('Values/View/value_org_link', array('org' => $target['org'], 'small' => true));
    }
    if (!empty($facts)) {
        $out .= '<span class="vp-claim-far"><i class="fas fa-arrow-right-long" aria-hidden="true"></i>'
            . implode('<span class="vp-claim-sep">·</span>', $facts) . '</span>';
    }
    return $out;
};

$facts = array();
if (!empty($claims)) {
    $facts[] = '<span class="eo-fact"><i class="fas fa-diagram-project" aria-hidden="true"></i>'
        . h(sprintf(__n('%s relationship', '%s relationships', count($claims)), number_format(count($claims)))) . '</span>';
    $facts[] = '<span class="eo-fact"><i class="fas fa-building" aria-hidden="true"></i>'
        . h(sprintf(__n('%s organisation', '%s organisations', $asserted['orgs']), number_format($asserted['orgs']))) . '</span>';
}
if ($replies > 0) {
    $facts[] = '<span class="eo-fact"><i class="fas fa-reply" aria-hidden="true"></i>'
        . h(sprintf(__n('%s reply', '%s replies', $replies), number_format($replies))) . '</span>';
}
$subtitle = empty($facts)
    ? h(__('No relationship asserted on this value'))
    : '<span class="eo-assessment-facts">' . implode('', $facts) . '</span>';

$addButton = function ($buttonClass) use ($addUrl) {
    return '<button type="button" class="btn btn-sm ' . $buttonClass . ' d-inline-flex align-items-center gap-1 flex-shrink-0"'
        . ' onclick="openModal(\'' . h($addUrl) . '\')" title="' . h(__('Assert a relationship on this value')) . '">'
        . '<i class="fas fa-plus" aria-hidden="true"></i><span class="eo-btn-label">' . h(__('Add')) . '</span></button>';
};

$headerExtra = '';
if (!empty($claims)) {
    $headerExtra .= '<div class="input-group input-group-sm eo-filter">'
        . '<span class="input-group-text border-end-0"><i class="fas fa-search text-muted small"></i></span>'
        . '<input type="search" class="form-control border-start-0 ps-0" data-vp-analyst-filter autocomplete="off"'
        . ' placeholder="' . h(__('Filter relationships…')) . '" aria-label="' . h(__('Filter relationships')) . '">'
        . '</div>';
    if ($outbound > 0 && $inbound > 0) {
        $headerExtra .= '<div class="vp-seg" role="group" aria-label="' . h(__('Direction')) . '">';
        foreach (array(
            'all' => sprintf(__('All %s'), count($claims)),
            'relationship' => sprintf(__('Outbound %s'), $outbound),
            'relationshipinbound' => sprintf(__('Inbound %s'), $inbound),
        ) as $key => $label) {
            $headerExtra .= '<button type="button" class="vp-seg-btn' . ($key === 'all' ? ' active' : '') . '"'
                . ' data-vp-ad-kind="' . h($key) . '" aria-pressed="' . ($key === 'all' ? 'true' : 'false') . '">'
                . h($label) . '</button>';
        }
        $headerExtra .= '</div>';
    }
    if ($canWrite) {
        $headerExtra .= $addButton('btn-outline-analystData');
    }
}
?>
<div class="card shadow-sm mb-3 vp-panel eo-assessment vp-analyst-card"
     style="--vp-panel-color: var(--analystData);"
     data-vp-analyst-claims
     data-vp-rel-summary="asserted"
     data-vp-rel-count="<?= h(number_format($asserted['total'])) ?>">

    <?= $this->element('Values/View/value_panel_header', array(
        'panelTitle' => __('Asserted by analysts'),
        'panelIcon' => 'fas fa-diagram-project',
        'panelColor' => 'var(--analystData)',
        'panelSub' => $subtitle,
        'panelExtra' => $headerExtra === '' ? null : $headerExtra,
    )) ?>

    <?php if (!empty($claims)): ?>
        <div class="eo-assessment-thread">
            <?= $this->element('AnalystData/thread', array(
                'analystData' => $links,
                'objectType' => 'AttributeValue',
                'objectUuid' => $hex,
                'showEmpty' => false,
                'entryContext' => $entryContext,
            )) ?>
        </div>
        <div class="eo-empty d-none" data-vp-analyst-none><?= __('No relationship matches.') ?></div>
    <?php elseif ($canWrite): ?>
        <div class="eo-prompt" style="--eo-prompt:var(--analystData);">
            <div class="eo-prompt-text">
                <div class="eo-prompt-title"><?= __('Nothing asserted yet') ?></div>
                <p><?= __('A relationship records how an analyst links this value to an event, an object, a cluster or another value. It is written on the value itself.') ?></p>
            </div>
            <?= $addButton('btn-analystData') ?>
        </div>
    <?php else: ?>
        <div class="vp-empty">
            <i class="fas fa-diagram-project" aria-hidden="true"></i>
            <span><?= __('No analyst has asserted a relationship for this value.') ?></span>
        </div>
    <?php endif; ?>

    <?php if (!empty($asserted['capped'])): ?>
        <div class="eo-card-foot">
            <span class="eo-legend"><i class="fas fa-circle-info" aria-hidden="true"></i><?= h(sprintf(
                __('Looked up on the %s most recent occurrences and their events and objects: a relationship written on an older one is not shown.'),
                number_format($asserted['occurrences'])
            )) ?></span>
        </div>
    <?php endif; ?>
</div>
