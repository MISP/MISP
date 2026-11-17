<?php
/*
 * One note, opinion, relationship or workspace in the card view of the
 * analyst data indexes, wired in through `card_element` (see
 * genericElementsBS5/IndexTable/index_card). Built on the events index's
 * card (Events/index_card, events-index-cards.css): the kind's icon gives way
 * to the selection box, the menu shows on hover, the record's own text leads
 * and opens it, then its creator org, its dates, what it is about
 * (AnalystData/target_ref), and a foot with what hangs off it and its
 * distribution.
 *
 * $analystTargets and $analystCounts come from AnalystDataController::index().
 */
App::uses('AnalystData', 'Model');
App::uses('EventCardTool', 'Tools/EventOverview');

$m = $modelSelection;
$record = $row[$m] ?? [];
if (empty($record['id'])) {
    return;
}
$ei = $this->EventIndex;
$id = (int)$record['id'];
$viewUrl = $baseurl . '/analystData/view/' . $m . '/' . $id;
$orgc = $record['Orgc'] ?? [];

$kinds = [
    'Note' => ['misp-icon misp-icon-analyst-note misp-simple', 'primary'],
    'Opinion' => ['misp-icon misp-icon-analyst-opinion misp-simple', 'success'],
    'Relationship' => ['fas fa-diagram-project', 'correlation'],
    'Workspace' => ['misp-icon misp-icon-analyst-graph misp-simple', 'analystGraph'],
];
list($icon, $colour) = $kinds[$m] ?? $kinds['Note'];

$target = function ($end) use ($record) {
    $type = (string)($record[$end . '_type'] ?? '');
    $isValue = in_array($type, AnalystData::SHA256_TARGETS, true);
    $address = (string)($record[AnalystData::addressColumn($type, $end)] ?? '');
    return $this->element('AnalystData/target_ref', [
        'type' => $type,
        'address' => $address,
        'target' => $this->viewVars['analystTargets'][$isValue ? strtolower($address) : $address] ?? null,
    ]);
};
$label = function ($icon, $text) {
    return '<dt class="dk-rl"><i class="' . h($icon) . '" aria-hidden="true"></i>' . h($text) . '</dt>';
};

// What the record says, linked to it: the link covers the card.
$main = function ($html, $title, $class = '') use ($viewUrl) {
    return sprintf(
        '<a class="adk-main %s" href="%s" title="%s" dir="auto">%s</a>',
        $class,
        h($viewUrl),
        h($title),
        $html
    );
};
$kick = '';
$head = '';
switch ($m) {
    case 'Note':
        $head = $main(h($record['note'] ?? ''), $record['note'] ?? '', 'adk-text is-note');
        if (!empty($record['language'])) {
            $kick = $this->element('genericElementsBS5/IndexTable/Fields/analyst_language', [
                'row' => $row,
                'field' => ['data_path' => $m . '.language'],
            ]);
        }
        break;
    case 'Opinion':
        $comment = (string)($record['comment'] ?? '');
        $head = $this->element('AnalystData/stance', ['score' => $record['opinion'] ?? 50])
            . $main($comment === '' ? '<span class="adk-none">' . h(__('No comment')) . '</span>' : h($comment), $comment, 'adk-text');
        break;
    case 'Relationship':
        $type = (string)($record['relationship_type'] ?? '');
        $head = $main(h($type === '' ? __('related') : $type), $type, 'adk-verb');
        break;
    case 'Workspace':
        $head = sprintf(
            '<span class="adk-thumb" data-intel-graph-thumb="%s" data-revision="%s" data-surface="index" data-name="%s"></span>',
            h($record['uuid']),
            h($record['revision'] ?? ''),
            h($record['name'] ?? '')
        ) . $main(h($record['name'] ?? ''), $record['name'] ?? '', 'adk-name');
        if (!empty($record['forked_from_uuid'])) {
            $parent = $record['forked_from'] ?? null;
            $kick = '<span class="adk-fork"><i class="fas fa-code-fork" aria-hidden="true"></i>'
                . ($parent === null
                    ? h(__('A fork'))
                    : sprintf('<a href="%s">%s</a>', h($baseurl . '/workspaces/view/' . $parent['uuid']), h($parent['name'])))
                . '</span>';
        }
        break;
}

// What hangs off the record: the thread it opens.
$counts = $analystCounts[$record['uuid'] ?? ''] ?? [];
$foot = '';
$open = sprintf(
    "event.preventDefault(); openModal('%s/analystData/viewForObject/%s/%s');",
    h($baseurl),
    h($m),
    h($record['uuid'] ?? '')
);
foreach ([
    'Note' => ['misp-icon misp-icon-analyst-note misp-simple text-primary', '%s note', '%s notes'],
    'Opinion' => ['misp-icon misp-icon-analyst-opinion misp-simple text-success', '%s opinion', '%s opinions'],
    'Relationship' => ['fas fa-diagram-project text-correlation', '%s relationship', '%s relationships'],
] as $type => list($countIcon, $one, $many)) {
    $n = (int)($counts[$type] ?? 0);
    $inner = '<i class="' . $countIcon . '" aria-hidden="true"></i><b>' . $n . '</b>';
    $title = $ei->plural($n, $one, $many);
    $foot .= $n === 0
        ? sprintf('<span class="dk-n is-zero" title="%s">%s</span>', h($title), $inner)
        : sprintf('<a class="dk-n" href="#" onclick="%s" title="%s">%s</a>', $open, h($title), $inner);
}

$created = strtotime((string)($record['created'] ?? '')) ?: 0;
$modified = strtotime((string)($record['modified'] ?? '')) ?: $created;
?>
<article class="dk-card adk-card" data-kind="<?= h($m) ?>" style="--adk-c: var(--bs-<?= h($colour) ?>)">
    <div class="dk-kick">
        <span class="dk-lead">
            <i class="<?= h($icon) ?>" aria-hidden="true"></i>
            <?php if (!empty($sections['selector'])): ?>
                <span class="dk-sel"><?= implode('', $sections['selector']) ?></span>
            <?php endif; ?>
        </span>
        <span class="dk-id">#<?= $id ?></span>
        <?php if ($kick !== ''): ?>
            <span class="adk-kick"><?= $kick ?></span>
        <?php endif; ?>
        <?php if (!empty($sections['extra'])): ?>
            <div class="dk-menu"><?= implode('', $sections['extra']) ?></div>
        <?php endif; ?>
    </div>

    <div class="adk-head"><?= $head ?></div>

    <div class="dk-org">
        <?= $ei->orgTile($orgc) ?>
        <?php if (!empty($orgc['id'])): ?>
            <a class="dk-orgname" href="<?= h($baseurl . '/organisations/view/' . $orgc['id']) ?>"
               title="<?= h(__('Created by %s', $orgc['name'] ?? '')) ?>"><?= h($orgc['name'] ?? '') ?></a>
        <?php else: ?>
            <span class="dk-orgname" title="<?= h(__('Created by %s', $orgc['name'] ?? '')) ?>"><?= h($orgc['name'] ?? '') ?></span>
        <?php endif; ?>
        <?= $ei->grade(null, $orgc, $orgGrading ?? null) ?>
    </div>

    <div class="dk-meta">
        <?php if ($created): ?>
            <span title="<?= h(__('Created %s', $ei->utc($created))) ?>"><i class="fa-regular fa-calendar"></i><?= h(date('j M Y', $created)) ?></span>
        <?php endif; ?>
        <?php if ($modified): ?>
            <span class="dk-when" title="<?= h(__('Last change %s', $ei->utc($modified))) ?>"><i class="fas fa-pen"></i><?= h(EventCardTool::ago($modified, time())) ?></span>
        <?php endif; ?>
        <?php if (!empty($record['authors'])): ?>
            <span class="dk-ext"><span title="<?= h(__('Authors: %s', $record['authors'])) ?>"><i class="fas fa-user-pen"></i><?= h($record['authors']) ?></span></span>
        <?php endif; ?>
    </div>

    <dl class="adk-rows">
        <?php if ($m === 'Relationship'): ?>
            <?= $label('fas fa-arrow-right-from-bracket', __('From')) ?>
            <dd><?= $target('object') ?></dd>
            <?= $label('fas fa-arrow-right-to-bracket', __('To')) ?>
            <dd><?= $target('related_object') ?></dd>
        <?php else: ?>
            <?= $label('fas fa-crosshairs', __('Target')) ?>
            <dd><?= $target('object') ?></dd>
        <?php endif; ?>
    </dl>

    <div class="dk-foot">
        <?= $foot ?>
        <?= $ei->distribution(EventCardTool::distribution((int)($record['distribution'] ?? 0), $record['SharingGroup'] ?? null)) ?>
    </div>
</article>
