<?php
/**
 * The Collaboration tab's Proposals card: the shadow attributes about this
 * value. A proposal is an edit somebody offered to an event, not analyst
 * data, so it has its own card rather than a place in the notes thread.
 *
 * Each operation keeps the colour the History tab gives the matching audit
 * action (AuditActionMeta): an addition is green, a replacement the primary
 * colour, a deletion red; a re-filing (category or type, same value) is grey.
 *
 * No proposal, no card. Lazily loaded from
 * ValuesController::viewAnalystProposals.
 *
 * @var array $valueIntelligence
 */
$proposals = $valueIntelligence['proposals'];
if (empty($proposals)) {
    return;
}

$ops = array(
    'replace' => array('label' => __('Replace'), 'icon' => 'fas fa-pencil-alt', 'tone' => 'primary',
        'title' => __('Replaces the attribute\'s value')),
    'delete' => array('label' => __('Delete'), 'icon' => 'fas fa-trash-alt', 'tone' => 'danger',
        'title' => __('Deletes the attribute')),
    'add' => array('label' => __('Add'), 'icon' => 'fas fa-plus-circle', 'tone' => 'success',
        'title' => __('Adds a new attribute holding this value')),
    'refile' => array('label' => __('Re-file'), 'icon' => 'fas fa-folder-open', 'tone' => 'secondary',
        'title' => __('Changes the category or type; the value stays')),
);

$open = 0;
$byOp = array();
foreach ($proposals as $item) {
    $p = $item['proposal'];
    if (empty($p['resolved'])) {
        $open++;
    }
    $byOp[$p['op']] = ($byOp[$p['op']] ?? 0) + 1;
}
$closed = count($proposals) - $open;
$subtitle = implode(' &nbsp;·&nbsp; ', array_filter(array(
    $open > 0 ? h(sprintf(__n('%s open', '%s open', $open), $open)) : null,
    $closed > 0 ? h(sprintf(__n('%s resolved', '%s resolved', $closed), $closed)) : null,
    h(__('edits offered to the events holding this value')),
)));

// One pill per kind of edit, in the header.
$tally = '';
foreach ($ops as $key => $op) {
    if (empty($byOp[$key])) {
        continue;
    }
    $tally .= '<span class="vp-prop-op is-' . h($op['tone']) . '" title="' . h($op['title']) . '">'
        . '<i class="' . h($op['icon']) . '" aria-hidden="true"></i>' . h($op['label'])
        . '<b>' . (int)$byOp[$key] . '</b></span>';
}
?>
<div class="card shadow-sm mb-3 vp-panel vp-proposals" style="--vp-panel-color: var(--vp-tl-proposal);">

    <?= $this->element('Values/View/value_panel_header', array(
        'panelTitle' => __('Proposals'),
        'panelIcon' => 'fas fa-code-pull-request',
        'panelColor' => 'var(--vp-tl-proposal)',
        'panelSub' => $subtitle,
        'panelExtra' => '<div class="vp-prop-tally">' . $tally . '</div>',
    )) ?>

    <div class="table-responsive">
        <table class="table align-middle mb-0 ix-table vp-prop-table">
            <thead>
                <tr>
                    <th scope="col"><?= __('Operation') ?></th>
                    <th scope="col"><?= __('Change') ?></th>
                    <th scope="col"><?= __('Category') ?></th>
                    <th scope="col"><?= __('Type') ?></th>
                    <th scope="col"><?= __('On') ?></th>
                    <th scope="col"><?= __('Proposed by') ?></th>
                    <th scope="col" title="<?= h(__('When the proposal last moved: MISP keeps no creation date, and a resolved proposal carries the day it closed.')) ?>"><?= __('Last moved') ?></th>
                    <th scope="col"><?= __('State') ?></th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($proposals as $item): ?>
                    <?php
                    $p = $item['proposal'];
                    $op = $ops[$p['op']] ?? $ops['replace'];
                    $resolved = !empty($p['resolved']);
                    ?>
                    <tr class="vp-prop-row is-<?= h($op['tone']) ?><?= $resolved ? ' is-resolved' : '' ?>">
                        <td class="vp-prop-opcell">
                            <span class="vp-prop-op is-<?= h($op['tone']) ?>" title="<?= h($op['title']) ?>">
                                <i class="<?= h($op['icon']) ?>" aria-hidden="true"></i><?= h($op['label']) ?>
                            </span>
                        </td>
                        <td class="vp-prop-change">
                            <div class="vp-prop-values">
                                <?php if ($p['op'] === 'replace'): ?>
                                    <span class="vp-prop-from" title="<?= h(__('Now')) ?>"><?= h($p['target']['value']) ?></span>
                                    <i class="fas fa-arrow-right vp-prop-arrow" aria-hidden="true"></i>
                                    <span class="vp-prop-to" title="<?= h(__('Proposed')) ?>"><?= h($p['value']) ?></span>
                                <?php elseif ($p['op'] === 'delete'): ?>
                                    <span class="vp-prop-gone"><?= h($p['target'] === null ? $p['value'] : $p['target']['value']) ?></span>
                                <?php elseif ($p['op'] === 'add'): ?>
                                    <span class="vp-prop-new"><?= h($p['value']) ?></span>
                                <?php else: ?>
                                    <span class="vp-prop-same"><?= h($p['value']) ?></span>
                                    <span class="vp-prop-note"><?= __('value unchanged') ?></span>
                                <?php endif; ?>
                            </div>
                            <?php if ($item['body'] !== ''): ?>
                                <div class="vp-prop-comment" title="<?= h(__('The proposer\'s comment')) ?>">
                                    <i class="fas fa-quote-left" aria-hidden="true"></i><span><?= h($item['body']) ?></span>
                                </div>
                            <?php endif; ?>
                        </td>
                        <td class="vp-prop-category"><?= h($p['category']) ?></td>
                        <td><span class="om-type"><?= h($p['type']) ?></span></td>
                        <td class="vp-prop-on">
                            <a href="<?= h($baseurl . '/events/view/' . (int)$p['event'] . ($p['target'] === null ? '' : '#tab-attributes')) ?>"
                               title="<?= h(__('Open the event, where its owner accepts or discards the proposal')) ?>">#<?= (int)$p['event'] ?></a>
                            <span><?= h($p['target'] === null
                                ? __('new attribute')
                                : sprintf(__('attribute %s'), $p['target']['id'])) ?></span>
                        </td>
                        <td>
                            <?= $this->element('Values/View/value_org_link', array(
                                'org' => array('id' => $item['org_id'] ?? null, 'name' => $item['org']),
                            )) ?>
                        </td>
                        <td class="vp-prop-date"><?= h($item['date']) ?></td>
                        <td>
                            <?php if ($resolved): ?>
                                <span class="vp-prop-state is-done"
                                      title="<?= h(__('Closed. MISP records only that it closed: accepting and discarding a proposal write the same column.')) ?>"><?= __('Resolved') ?></span>
                            <?php else: ?>
                                <span class="vp-prop-state"
                                      title="<?= h(__('Nobody has accepted or discarded this yet.')) ?>"><i class="fas fa-circle" aria-hidden="true"></i><?= __('Open') ?></span>
                            <?php endif; ?>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>
