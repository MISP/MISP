<?php
/**
 * The History tab's body: the value's audit trail grouped by occurrence,
 * with an organisation and a field grouping a click away, and the entries
 * that belong to no single occurrence in a section of their own.
 *
 * Drawn under the audit log's filter bar (AuditLogs/value_history), whose
 * filters have already narrowed `$history`. The sections, their pages and the
 * groupings are value-intelligence.js's (`data-vp-audit-*`, `data-vp-list`).
 *
 * @var array $history ValueIntelligence::forHistory()['history']
 * @var bool $filtered Whether the bar narrowed it
 */
App::uses('AuditActionMeta', 'Tools/ValueIntelligence');

$filtered = !empty($filtered);
$panelColour = 'var(--bs-secondary-color)';
$panelIcon = 'fas fa-history';
// Entries per section page, and sections per page.
$pageSize = 8;
$sectionSize = 8;

$fmt = function ($stamp, $format) {
    $at = strtotime((string)$stamp);
    return $at ? date($format, $at) : (string)$stamp;
};
$deletedBadge = function () {
    return '<span class="vp-hx-del" title="' . h(__('Soft-deleted — history, not current state')) . '">'
        . '<i class="fas fa-trash" aria-hidden="true"></i>' . h(__('Deleted')) . '</span>';
};
?>
<?php if (!$history['recorded']): ?>
    <?php
    $knowable = $history['knowable'];
    $edited = $knowable['edited'];
    $publications = $knowable['publications'];
    ?>
    <div class="card shadow-sm mb-3 vp-panel" style="--vp-panel-color: <?= h($panelColour) ?>;">
        <?= $this->element('Values/View/value_panel_header', array(
            'panelTitle' => __('History'),
            'panelIcon' => $panelIcon,
            'panelColor' => $panelColour,
            'panelSub' => h(__('Not recorded on this instance')),
        )) ?>
        <div class="p-3 d-flex flex-column gap-3">
            <div class="vp-panel-stub">
                <span class="vp-panel-stub-badge"><?= __('Not recorded') ?></span>
                <div class="fw-bold mt-2"><?= __('This instance is not recording an audit log.') ?></div>
                <div class="vp-panel-stub-note">
                    <?= sprintf(
                        __('Turn it on at %s. It records from then on and never reconstructs the past.'),
                        '<code>' . h(__('Administration → Server settings → MISP → MISP.log_new_audit')) . '</code>'
                    ) ?>
                </div>
            </div>
            <div>
                <div class="vp-subhead"><?= __('Knowable without it') ?></div>
                <?php if (!empty($knowable['with_created'])): ?>
                    <div class="vp-fact-line">
                        <i class="fas fa-circle-plus"></i>
                        <span><?= h(sprintf(__('First occurrence added %s'), date('j M Y', $knowable['added']))) ?></span>
                    </div>
                <?php endif; ?>
                <?php if ($edited !== null): ?>
                    <div class="vp-fact-line">
                        <i class="fas fa-pencil"></i>
                        <span><?= h(sprintf(__('Most recent edit to an occurrence %s'), date('j M Y', $edited))) ?></span>
                    </div>
                <?php endif; ?>
                <?php if (!empty($publications)): ?>
                    <div class="vp-fact-line">
                        <i class="fas fa-paper-plane"></i>
                        <span><?= h(sprintf(
                            __('Published %1$s → %2$s'),
                            date('j M Y', $publications[0]),
                            date('j M Y', $publications[count($publications) - 1])
                        )) ?></span>
                    </div>
                <?php endif; ?>
                <div class="vp-fact-line">
                    <i class="misp-icon misp-icon-sighting misp-simple"></i>
                    <span><?= h(sprintf(__n('%d sighting', '%d sightings', $knowable['sightings']), $knowable['sightings'])) ?></span>
                </div>
                <div class="vp-aside-note">
                    <?= sprintf(__('All of these are on the %s tab.'), '<a href="#tab-timeline">' . h(__('Timeline')) . '</a>') ?>
                </div>
            </div>
        </div>
    </div>

<?php elseif ($history['entries'] === 0): ?>
    <div class="card shadow-sm mb-3 vp-panel" style="--vp-panel-color: <?= h($panelColour) ?>;">
        <?= $this->element('Values/View/value_panel_header', array(
            'panelTitle' => __('History'),
            'panelIcon' => $panelIcon,
            'panelColor' => $panelColour,
            'panelSub' => h($filtered ? __('No entry matches these filters') : __('Nothing logged')),
        )) ?>
        <div class="vp-empty">
            <i class="<?= h($panelIcon) ?>"></i>
            <span><?= h($filtered
                ? __('No entry of this value\'s history matches these filters.')
                : __('The audit log is running and has no entry for this value. Nothing you can read has been touched since recording began.')) ?></span>
        </div>
    </div>

<?php else: ?>
<?php
$vocab = $history['vocab']['action'];
$orgBody = function ($orgId) {
    return 'vp-audit-org-' . (int)$orgId;
};
$fieldBody = function ($key) {
    return 'vp-audit-field-' . substr(md5($key), 0, 12);
};

/**
 * One audit entry. The data attributes are what the groupings, the pages and
 * the diff toggle in value-intelligence.js read.
 */
$renderRow = function ($row, $home) use ($baseurl, $fmt, $orgBody, $fieldBody) {
    $meta = AuditActionMeta::forAction($row['action']);
    $fields = array();
    foreach ($row['change'] ?? array() as $change) {
        $fields[] = $change['field'];
    }
    $actor = $row['actor'] !== null ? $row['actor'] : sprintf(__('%s (unnamed)'), $row['org']);
    $slug = function ($text) {
        return trim(preg_replace('/[^a-z0-9]+/', '-', strtolower((string)$text)), '-');
    };
    $tokens = array(
        'action:' . preg_replace('/[^a-z0-9]+/', '-', $row['action']),
        'model:' . strtolower($row['model']),
        'org:' . $slug($row['org']),
        'actor:' . $slug($actor),
    );
    $blob = strtolower(trim(implode(' ', array(
        $meta['label'], (string)$row['subject'], (string)$row['model_title'],
        $actor, $row['org'], (string)$row['note'], implode(' ', $fields),
    ))));
    $recordUrl = null;
    if ($row['model'] === 'EventReport' && $row['model_id'] !== null) {
        $recordUrl = $baseurl . '/eventReports/view/' . (int)$row['model_id'];
    } elseif ($row['event_id'] !== null) {
        $recordUrl = $baseurl . '/events/view/' . (int)$row['event_id'];
    }
    $shownFields = array_slice($fields, 0, 4);
    $moreFields = count($fields) - count($shownFields);
    ob_start();
    ?>
    <div class="vp-audit-row"
         style="<?= AuditActionMeta::style($row['action']) ?>"
         data-vp-list-row
         data-vp-audit-home="<?= h($home) ?>"
         data-vp-audit-org="<?= h($orgBody($row['org_id'])) ?>"
         data-vp-audit-field="<?= h($fieldBody($row['field_key']['key'])) ?>"
         <?= strpos($row['field_key']['key'], 'field:') === 0 ? 'data-vp-audit-edit' : '' ?>
         data-vp-facet="<?= h(implode(' ', $tokens)) ?>"
         data-vp-time="<?= h($fmt($row['created'], 'YmdHi')) ?>"
         data-vp-text="<?= h($blob) ?>"
         <?= $row['renamed'] ? 'data-vp-audit-renamed' : '' ?>>

        <div class="vp-hx-when" title="<?= h($fmt($row['created'], 'j M Y H:i:s')) ?>">
            <span><?= h($fmt($row['created'], 'j M Y')) ?></span>
            <b><?= h($fmt($row['created'], 'H:i')) ?></b>
        </div>

        <span class="vp-audit-act" title="<?= h($meta['label']) ?>">
            <i class="<?= h($meta['icon']) ?>" aria-hidden="true"></i>
        </span>

        <div class="vp-hx-main">
            <div class="vp-hx-line">
                <span class="vp-hx-what">
                    <b class="vp-hx-verb"><?= h($meta['label']) ?></b>
                    <?php if (!empty($shownFields)): ?>
                        <?php foreach ($shownFields as $field): ?>
                            <code class="vp-hx-field"><?= h($field) ?></code>
                        <?php endforeach; ?>
                        <?php if ($moreFields > 0): ?>
                            <span class="vp-hx-more" title="<?= h(implode(', ', array_slice($fields, 4))) ?>">
                                <?= h(sprintf(__('+%d'), $moreFields)) ?>
                            </span>
                        <?php endif; ?>
                    <?php elseif ($row['subject'] !== null): ?>
                        <span class="vp-hx-subject"><?= h($row['subject']) ?></span>
                    <?php endif; ?>
                    <?php if ((int)$row['request_type'] === 1): ?>
                        <span class="vp-hx-via" title="<?= h(__('Made through the API, not the web interface')) ?>"><?= __('API') ?></span>
                    <?php elseif ((int)$row['request_type'] === 2): ?>
                        <span class="vp-hx-via" title="<?= h(__('Made from the command line or a background job')) ?>"><?= __('CLI') ?></span>
                    <?php endif; ?>
                </span>
                <span class="vp-hx-who<?= $row['actor'] === null ? ' is-unnamed' : '' ?>"
                      <?= $row['actor'] === null ? 'title="' . h(__('MISP does not hand you the user on an entry from outside your organisation')) . '"' : '' ?>>
                    <i class="fas fa-user" aria-hidden="true"></i><span><?= h($row['actor'] !== null ? $row['actor'] : __('unnamed user')) ?></span>
                    <i class="misp-icon misp-icon-organisation misp-simple" aria-hidden="true"></i><span><?= h($row['org']) ?></span>
                </span>
                <?php if (!empty($row['change'])): ?>
                    <button type="button" class="vp-hx-diff" data-vp-audit-diff aria-expanded="false"
                            title="<?= h(__('Show what changed')) ?>" aria-label="<?= h(__('Show what changed')) ?>">
                        <i class="fas fa-chevron-down" aria-hidden="true"></i>
                    </button>
                <?php else: ?>
                    <span class="vp-hx-diff is-none" aria-hidden="true"></span>
                <?php endif; ?>
            </div>
            <?php if ($row['model_title'] !== null): ?>
                <?php
                $recordLine = h($row['model']) . ($row['model_id'] !== null ? ' #' . h($row['model_id']) : '')
                    . ' · ' . h($row['model_title']);
                ?>
                <div class="vp-hx-record">
                    <?php if ($recordUrl !== null): ?>
                        <a href="<?= h($recordUrl) ?>" title="<?= h($row['model'] === 'EventReport'
                            ? __('Open this event report') : __('Open the event holding it')) ?>"><?= $recordLine ?></a>
                    <?php else: ?>
                        <?= $recordLine ?>
                    <?php endif; ?>
                </div>
            <?php endif; ?>
            <?php if ($row['note'] !== null): ?>
                <div class="vp-hx-note"><?= h($row['note']) ?></div>
            <?php endif; ?>
            <?php if ($row['renamed']): ?>
                <div class="vp-fact-line vp-fact-line-warn mt-1">
                    <i class="fas fa-triangle-exclamation"></i>
                    <span><?= __('This occurrence used to hold a different value. Only this entry and the ones above it belong to this value; older entries are filed under the old one.') ?></span>
                </div>
            <?php endif; ?>
            <?php if (!empty($row['change'])): ?>
                <?= $this->element('Values/View/value_change_table', array(
                    'changes' => $row['change'],
                    'class' => 'd-none',
                )) ?>
            <?php endif; ?>
        </div>
    </div>
    <?php
    return ob_get_clean();
};

/**
 * The share of each action in a section, as one thin bar.
 */
$renderMix = function ($mix, $total) use ($vocab) {
    if ($total < 1) {
        return '';
    }
    $segments = '';
    $legend = array();
    foreach ($vocab as $action) {
        if (empty($mix[$action])) {
            continue;
        }
        $share = round(($mix[$action] / $total) * 100, 2);
        $segments .= '<span style="' . AuditActionMeta::style($action) . ' --vp-audit-share: ' . $share . '%;"></span>';
        $legend[] = AuditActionMeta::label($action) . ' ' . $mix[$action];
    }
    return '<span class="vp-audit-mix" title="' . h(implode(' · ', $legend)) . '">' . $segments . '</span>';
};

/**
 * A section's entry count, which the list script rewrites while it pages.
 */
$renderCount = function ($count) {
    $plain = sprintf(__n('%d entry', '%d entries', $count), $count);
    return '<span class="vp-hx-count" data-vp-audit-count data-vp-audit-plain="' . h($plain) . '"'
        . ' data-vp-audit-tpl="' . h(__n('%1$s of %2$s entry', '%1$s of %2$s entries', $count)) . '">'
        . h($plain) . '</span>';
};

$headerLine = implode(' &nbsp;·&nbsp; ', array_filter(array(
    h(sprintf(__n('%s entry', '%s entries', $history['entries']), number_format($history['entries']))),
    $history['occurrences'] > 0
        ? h(sprintf(__n('%d occurrence', '%d occurrences', $history['occurrences']), $history['occurrences']))
        : null,
    h(sprintf(__n('%d event', '%d events', $history['events']), $history['events'])),
    $history['capped'] ? h(sprintf(__('the %s most recent shown'), number_format($history['shown']))) : null,
)));

ob_start();
?>
    <div class="vp-seg" role="group" aria-label="<?= h(__('Grouping')) ?>">
        <?php foreach (array(
            'occurrence' => __('By occurrence'),
            'org' => __('By organisation'),
            'field' => __('By field'),
        ) as $key => $label): ?>
            <button type="button" class="vp-seg-btn<?= $key === 'occurrence' ? ' active' : '' ?>"
                    data-vp-audit-group="<?= h($key) ?>"
                    aria-pressed="<?= $key === 'occurrence' ? 'true' : 'false' ?>"><?= h($label) ?></button>
        <?php endforeach; ?>
    </div>
    <button type="button" class="vp-head-btn" data-vp-audit-expand-all
            data-vp-audit-label-expand="<?= h(__('Expand all')) ?>"
            data-vp-audit-label-collapse="<?= h(__('Collapse all')) ?>">
        <i class="fas fa-up-down" aria-hidden="true"></i>
        <span data-vp-audit-expand-label><?= __('Expand all') ?></span>
    </button>
<?php
$headerExtra = ob_get_clean();
?>
<div class="card shadow-sm mb-3 vp-panel vp-hx" style="--vp-panel-color: <?= h($panelColour) ?>;"
     data-vp-list data-vp-audit>

    <?= $this->element('Values/View/value_panel_header', array(
        'panelTitle' => __('History'),
        'panelIcon' => $panelIcon,
        'panelColor' => $panelColour,
        'panelSub' => $headerLine,
        'panelExtra' => $headerExtra,
    )) ?>

    <?php if ($history['outside'] > 0): ?>
        <div class="vp-hx-band" data-vp-audit-elided>
            <i class="fas fa-circle-info" aria-hidden="true"></i>
            <span>
                <?= h($history['capped']
                    ? sprintf(
                        __n('%1$d of the %2$d occurrences you can read has no section: its entries are older than the newest this tab reads.',
                            '%1$d of the %2$d occurrences you can read have no section: their entries are older than the newest this tab reads.',
                            $history['outside']),
                        $history['outside'], $history['visible'])
                    : sprintf(
                        __n('%1$d of the %2$d occurrences you can read has no entry here.',
                            '%1$d of the %2$d occurrences you can read have no entry here.',
                            $history['outside']),
                        $history['outside'], $history['visible'])) ?>
                <span class="d-none" data-vp-audit-dropped
                      data-vp-audit-drop-period-one="<?= h(__('%1$s of the sections below has no entry between %2$s and %3$s.')) ?>"
                      data-vp-audit-drop-period-many="<?= h(__('%1$s of the sections below have no entry between %2$s and %3$s.')) ?>"
                      data-vp-audit-drop-plain-one="<?= h(__('%1$s of the sections below has no entry matching these filters.')) ?>"
                      data-vp-audit-drop-plain-many="<?= h(__('%1$s of the sections below have no entry matching these filters.')) ?>"></span>
            </span>
        </div>
    <?php endif; ?>

    <div data-vp-list-rows>

        <div data-vp-audit-grouping="occurrence">
            <?php foreach ($history['groups'] as $index => $group): ?>
                <?php
                $sectionId = 'vp-audit-' . (int)$group['attribute_id'];
                // The first section opens, the rest wait to be asked.
                $open = $index === 0;
                ?>
                <div class="vp-hx-sec" data-vp-audit-section data-vp-audit-total="<?= h($group['count']) ?>">
                    <div class="vp-hx-head">
                        <button type="button" class="vp-hx-toggle" data-vp-audit-toggle
                                aria-expanded="<?= $open ? 'true' : 'false' ?>" aria-controls="<?= h($sectionId) ?>">
                            <i class="fas fa-chevron-<?= $open ? 'down' : 'right' ?>" data-vp-audit-chevron aria-hidden="true"></i>
                            <span class="vp-hx-ref">#<?= h($group['event_id']) ?></span>
                        </button>
                        <div class="vp-hx-title">
                            <a class="vp-hx-event" href="<?= h($baseurl . '/events/view/' . (int)$group['event_id']) ?>"
                               title="<?= h(__('Open the event holding this occurrence')) ?>"><?= h($group['event_info']) ?></a>
                            <div class="vp-hx-sub">
                                <?= $this->element('Values/View/value_org_link', array(
                                    'org' => array('id' => $group['org_id'] ?? null, 'name' => $group['org']),
                                    'small' => true,
                                )) ?>
                                <?php if (!empty($group['type'])): ?>
                                    <span class="om-type"><?= h($group['type']) ?></span>
                                <?php endif; ?>
                                <span class="vp-hx-attr"><?= h(sprintf(__('attribute #%s'), $group['attribute_id'])) ?></span>
                                <?php if ($group['deleted']): ?>
                                    <?= $deletedBadge() ?>
                                <?php endif; ?>
                            </div>
                        </div>
                        <div class="vp-hx-tally"<?= $group['total'] > $group['count']
                            ? ' title="' . h(sprintf(__n('%d entry on this occurrence over the whole log', '%d entries on this occurrence over the whole log', $group['total']), $group['total'])) . '"'
                            : '' ?>>
                            <?= $renderMix($group['mix'], $group['count']) ?>
                            <?= $renderCount($group['count']) ?>
                        </div>
                        <div class="vp-hx-last">
                            <?php if ($group['last'] !== null): ?>
                                <span title="<?= h(__('Last entry')) ?>"><?= h($fmt($group['last'], 'j M Y')) ?></span>
                            <?php else: ?>
                                <em><?= __('nothing logged') ?></em>
                            <?php endif; ?>
                        </div>
                    </div>
                    <div id="<?= h($sectionId) ?>" class="vp-hx-body<?= $open ? '' : ' d-none' ?>" data-vp-audit-body>
                        <?php foreach ($group['entries'] as $row): ?>
                            <?= $renderRow($row, $sectionId) ?>
                        <?php endforeach; ?>
                        <?php if ($group['count'] > $pageSize): ?>
                            <div class="vp-hx-pager" data-vp-audit-pagerhost>
                                <?= $this->element('Values/View/value_pager', array(
                                    'size' => $pageSize,
                                    'shown' => $group['count'],
                                    'total' => $group['count'],
                                    'noun' => array('one' => __('entry'), 'many' => __('entries')),
                                )) ?>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
            <?php endforeach; ?>

            <?php if ($history['occurrences'] > $sectionSize): ?>
                <div class="vp-hx-pager" data-vp-audit-sectionpager>
                    <?= $this->element('Values/View/value_pager', array(
                        'size' => $sectionSize,
                        'shown' => $history['occurrences'],
                        'total' => $history['occurrences'],
                        'noun' => array('one' => __('occurrence'), 'many' => __('occurrences')),
                    )) ?>
                </div>
            <?php endif; ?>

            <?php if (!empty($history['event_entries'])): ?>
                <?php $eventTotal = count($history['event_entries']); ?>
                <div class="vp-hx-sec is-pinned" data-vp-audit-section data-vp-audit-pinned
                     data-vp-audit-total="<?= h($eventTotal) ?>">
                    <div class="vp-hx-head">
                        <button type="button" class="vp-hx-toggle" data-vp-audit-toggle
                                aria-expanded="false" aria-controls="vp-audit-events">
                            <i class="fas fa-chevron-right" data-vp-audit-chevron aria-hidden="true"></i>
                            <i class="fas fa-layer-group vp-hx-pin" aria-hidden="true"></i>
                        </button>
                        <div class="vp-hx-title">
                            <span class="vp-hx-event"><?= __('Not tied to one occurrence') ?></span>
                            <div class="vp-hx-sub">
                                <?= __('Publications and tags of its events, the objects it sits in, proposals and event reports: each counted once here.') ?>
                            </div>
                        </div>
                        <div class="vp-hx-tally"><?= $renderCount($eventTotal) ?></div>
                        <div class="vp-hx-last"></div>
                    </div>
                    <div id="vp-audit-events" class="vp-hx-body d-none" data-vp-audit-body>
                        <?php foreach ($history['event_entries'] as $row): ?>
                            <?= $renderRow($row, 'vp-audit-events') ?>
                        <?php endforeach; ?>
                        <?php if ($eventTotal > $pageSize): ?>
                            <div class="vp-hx-pager" data-vp-audit-pagerhost>
                                <?= $this->element('Values/View/value_pager', array(
                                    'size' => $pageSize,
                                    'shown' => $eventTotal,
                                    'total' => $eventTotal,
                                    'noun' => array('one' => __('entry'), 'many' => __('entries')),
                                )) ?>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
            <?php endif; ?>
        </div>

        <?php foreach (array('org', 'field') as $grouping): ?>
            <?= $this->element('Values/View/value_history_regroup', array(
                'grouping' => $grouping,
                'sections' => $grouping === 'org' ? $history['regroups']['orgs'] : $history['regroups']['fields'],
                'bodyId' => $grouping === 'org' ? $orgBody : $fieldBody,
                'renderMix' => $renderMix,
                'renderCount' => $renderCount,
                'fmt' => $fmt,
                'pageSize' => $pageSize,
                'sectionSize' => $sectionSize,
            )) ?>
        <?php endforeach; ?>

    </div>

    <div class="vp-empty d-none" data-vp-list-empty>
        <i class="fas fa-filter"></i>
        <span><?= __('No entry matches these filters.') ?></span>
    </div>

    <div class="vp-hx-foot">
        <i class="fas fa-user-shield" aria-hidden="true"></i>
        <span><?= __('Scoped to what you may read: every entry on events your organisation created, and on the others the event-level entries plus the entries on occurrences you may read.') ?></span>
    </div>

</div>
<?php endif; ?>
