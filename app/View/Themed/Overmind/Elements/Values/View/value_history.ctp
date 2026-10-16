<?php
/**
 * The History tab: the audit log for this value, one collapsible section
 * per occurrence.
 *
 * Grouping by occurrence is the whole addition over the per-event audit
 * logs the analyst already has. Those can each see one copy of this
 * value; only this page can say that occurrence 4831022 carries nine
 * entries while 4828810 carries two.
 *
 * Three things follow from the grouping rather than decorate it. Event
 * publications and event tags get their own section, because repeating
 * ten of them inside six sections would turn ten entries into sixty.
 * The occurrences hidden by ACL are named and not listed, because six
 * sections where there should be ten is the one place that absence has
 * a visible shape. And a section's counts move with the rail, because a
 * header reading `9 entries` over three visible rows is two numbers
 * disagreeing.
 *
 * The panel owns its own row — rail at col-lg-3, sections at col-lg-9 —
 * rather than taking `view_layout`'s split: the facet control binds a
 * checkbox to rows through the nearest `data-vp-list` ancestor, so the
 * two cannot be separate cards.
 *
 * Lazily loaded into `.ajax-tab-content` from
 * ValuesController::viewHistory.
 *
 * @var array $valueIntelligence
 * @var string $valueB64
 */
App::uses('AuditActionMeta', 'Tools/ValueIntelligence');

$profile = $valueIntelligence;
$history = $profile['history'];

$panelColour = 'var(--bs-secondary-color)';
$panelIcon = 'fas fa-history';

/*
 * Rows page inside their own section and never across the union: a
 * server-side Paginator over N event-scoped queries has no stable
 * ordering key, and this is where that lands.
 *
 * Eight rather than phase 16's twenty-five, and the same eight the
 * sections themselves page at. A pager over sections and a pager over
 * rows are two controls a reader meets in one column, and giving them
 * different strides makes the second one read as a different kind of
 * thing than the first.
 */
$pageSize = 8;

/*
 * How many occurrence sections a page of them holds. Not a count of
 * entries — an occurrence with four changes and one with forty are one
 * section each, and this control is over sections.
 */
$sectionSize = 8;

/**
 * @param string $stamp `Y-m-d H:i:s`
 * @param string $format
 * @return string
 */
$fmt = function ($stamp, $format) {
    $at = strtotime((string)$stamp);
    return $at ? date($format, $at) : (string)$stamp;
};

/**
 * The `Del` badge the Occurrences tab already uses, so a soft-deleted
 * occurrence looks the same on both tabs.
 *
 * @return string
 */
$deletedBadge = function () {
    return '<span class="badge d-inline-flex align-items-center gap-1'
        . ' bg-secondary-subtle text-secondary-emphasis border'
        . ' border-secondary-subtle" title="'
        . h(__('Soft-deleted — history, not current state')) . '">'
        . '<i class="fas fa-trash"></i>' . h(__('Del')) . '</span>';
};
?>

<?php if (!$history['recorded']): ?>
    <?php
    /*
     * State 2, and the common case rather than the edge one:
     * `MISP.log_new_audit` defaults to false (`Server.php:6649`), so
     * this is what a default instance renders. It replaces the panel
     * instead of sitting inside it, because every section, count and
     * facet below would otherwise be a claim about a log that is not
     * running.
     *
     * The rail card is the point of the state. "No history" invites the
     * reader to conclude nothing happened; the answer is the list of
     * what this page still knows without the audit log — and it is not
     * a short list.
     */
    /*
     * The facts the card lists, supplied by `forHistory` rather than
     * reassembled from the whole profile here. This state is the only
     * one that needs them, and the only one where paying for them is
     * free: with `MISP.log_new_audit` off there is no audit read to run.
     */
    $knowable = $history['knowable'];
    $edited = $knowable['edited'];
    $publications = $knowable['publications'];
    ?>
    <div class="row">
        <div class="col-lg-8">
            <div class="card shadow-sm mb-3 vp-panel"
                 style="--vp-panel-color: <?= h($panelColour) ?>;">
                <?= $this->element('Values/View/value_panel_header', array(
                    'panelTitle' => __('History'),
                    'panelIcon' => $panelIcon,
                    'panelColor' => $panelColour,
                )) ?>
                <div class="p-3">
                    <div class="vp-panel-stub">
                        <span class="vp-panel-stub-badge">
                            <?= __('Not recorded') ?>
                        </span>
                        <div class="fw-bold mt-2">
                            <?= __(
                                'This instance is not recording an audit'
                                . ' log.'
                            ) ?>
                        </div>
                        <div class="vp-panel-stub-note">
                            <?= __(
                                'Which is not the same as nothing having'
                                . ' happened to this value. Everything'
                                . ' below happened; none of it was'
                                . ' written down.'
                            ) ?>
                        </div>
                    </div>

                    <div class="vp-fact-line mt-3">
                        <i class="fas fa-sliders"></i>
                        <span>
                            <?= sprintf(
                                __('Turn it on at %s.'),
                                '<code>' . h(__(
                                    'Administration → Server settings →'
                                    . ' MISP → MISP.log_new_audit'
                                )) . '</code>'
                            ) ?>
                        </span>
                    </div>
                    <div class="vp-fact-line vp-fact-line-warn">
                        <i class="fas fa-triangle-exclamation"></i>
                        <span>
                            <?= __(
                                'Enabling it records forward. It never'
                                . ' reconstructs the past — an analyst'
                                . ' who turns it on today and comes'
                                . ' back in a year has a year of'
                                . ' history, not this value\'s.'
                            ) ?>
                        </span>
                    </div>
                </div>
            </div>
        </div>
        <div class="col-lg-4">
            <div class="vp-aside">
                <div class="vp-aside-head">
                    <span class="vp-aside-title">
                        <?= __('Knowable without it') ?>
                    </span>
                </div>
                <div class="vp-aside-note">
                    <?= __(
                        'None of these come from the audit log, so none'
                        . ' of them are affected by the setting.'
                    ) ?>
                </div>
                <div class="vp-fact-line">
                    <i class="fas fa-pencil"></i>
                    <span>
                        <?= h(sprintf(
                            __n(
                                'The latest edit to each of %d'
                                . ' occurrence',
                                'The latest edit to each of %d'
                                . ' occurrences',
                                $knowable['occurrences']
                            ),
                            $knowable['occurrences']
                        )) ?>
                        <?php if ($edited !== null): ?>
                            <span class="vp-fact-line-sub">
                                <?= h(sprintf(
                                    __('most recent %s'),
                                    date('j M Y', $edited)
                                )) ?>
                            </span>
                        <?php endif; ?>
                    </span>
                </div>
                <?php if (!empty($publications)): ?>
                    <div class="vp-fact-line">
                        <i class="fas fa-paper-plane"></i>
                        <span>
                            <?= __('First and last publication') ?>
                            <span class="vp-fact-line-sub">
                                <?= h(sprintf(
                                    '%1$s → %2$s',
                                    date('j M Y', $publications[0]),
                                    date(
                                        'j M Y',
                                        $publications[
                                            count($publications) - 1
                                        ]
                                    )
                                )) ?>
                            </span>
                        </span>
                    </div>
                <?php endif; ?>
                <div class="vp-fact-line">
                    <i class="misp-icon misp-icon-sighting misp-simple">
                    </i>
                    <span>
                        <?= h(sprintf(
                            __('%d sightings, each to the minute'),
                            $knowable['sightings']
                        )) ?>
                    </span>
                </div>
                <div class="vp-aside-note">
                    <?= sprintf(
                        __('All three are on the %s tab.'),
                        '<a href="#tab-timeline">'
                        . h(__('Timeline')) . '</a>'
                    ) ?>
                </div>
            </div>
        </div>
    </div>

<?php elseif ($history['entries'] === 0): ?>
    <?php
    /*
     * State 3. Recorded, and nothing about this value — which is a
     * claim about the value, where state 2 is a claim about the
     * instance. The wording has to make that the first thing the
     * reader takes away, because the two look identical otherwise.
     *
     * Keyed on the corpus and not on the window, so it stays a claim
     * about the value: an empty *period* over a log that has entries is
     * the state further down, and it says something different.
     */
    ?>
    <div class="card shadow-sm mb-3 vp-panel"
         style="--vp-panel-color: <?= h($panelColour) ?>;">
        <?= $this->element('Values/View/value_panel_header', array(
            'panelTitle' => __('History'),
            'panelIcon' => $panelIcon,
            'panelColor' => $panelColour,
            'panelSub' => __('Nothing logged'),
        )) ?>
        <div class="vp-empty">
            <i class="<?= h($panelIcon) ?>"></i>
            <span>
                <?= __(
                    'The audit log is running on this instance and has'
                    . ' no entry here for this value. Nothing you can'
                    . ' read has been touched since recording began.'
                ) ?>
            </span>
        </div>
    </div>

<?php else: ?>
<?php
/*
 * State 1. Everything below is derived from `groups` and
 * `event_entries` — the header, the section counts, the mixes and the
 * four facet groups are four readings of one pair of lists, so adding
 * an entry moves all four by one and no two of them can drift.
 */
$facets = $history['facets'];
$vocab = $history['vocab']['action'];

/*
 * The body each row moves into when the reader regroups, by id, so the
 * script needs no knowledge of how a key was spelled.
 */
$orgBody = function ($orgId) {
    return 'vp-audit-org-' . (int)$orgId;
};
$fieldBody = function ($key) {
    return 'vp-audit-field-' . substr(md5($key), 0, 12);
};

/**
 * One row. Kept as a closure rather than a second element file: the
 * occurrence sections and the event-level section draw the same row,
 * and the only difference between them is what the row is filed under.
 *
 * @param array $row
 * @return string
 */
$renderRow = function ($row, $home) use ($baseurl, $fmt, $orgBody,
    $fieldBody
) {
    $meta = AuditActionMeta::forAction($row['action']);
    $fields = array();
    if (!empty($row['change'])) {
        foreach ($row['change'] as $change) {
            $fields[] = $change['field'];
        }
    }
    /*
     * The title is composed from what the row already carries rather
     * than written out: an edit names the fields in its own diff, a tag
     * or galaxy names its subject, and everything else is its action
     * and nothing more. A title stored beside the diff is a title that
     * eventually contradicts it.
     */
    $title = $meta['label'];
    if (!empty($fields)) {
        $title .= ' ' . implode(', ', $fields);
    } elseif ($row['subject'] !== null) {
        $title .= ' ' . $row['subject'];
    }

    $actor = $row['actor'] !== null
        ? $row['actor']
        : sprintf(__('%s (unnamed)'), $row['org']);
    $tokens = array(
        'action:' . preg_replace('/[^a-z0-9]+/', '-', $row['action']),
        'model:' . strtolower($row['model']),
        'org:' . trim(preg_replace(
            '/[^a-z0-9]+/',
            '-',
            strtolower($row['org'])
        ), '-'),
        'actor:' . trim(preg_replace(
            '/[^a-z0-9]+/',
            '-',
            strtolower($actor)
        ), '-'),
    );
    $blob = strtolower(trim(implode(' ', array(
        $title,
        (string)$row['model_title'],
        $actor,
        $row['org'],
        (string)$row['note'],
        implode(' ', $fields),
    ))));

    ob_start();
    ?>
    <?php
    /*
     * Phase 15's `.vp-audit-row` grid, not a second one: time, glyph,
     * everything else. The Timeline's chronology draws the same three
     * tracks, which is why that phase built the class here rather than
     * in its own family.
     */
    ?>
    <div class="vp-audit-row"
         data-vp-list-row
         data-vp-audit-home="<?= h($home) ?>"
         data-vp-audit-org="<?= h($orgBody($row['org_id'])) ?>"
         data-vp-audit-field="<?= h($fieldBody($row['field_key']['key'])) ?>"
         <?= strpos($row['field_key']['key'], 'field:') === 0
             ? 'data-vp-audit-edit' : '' ?>
         data-vp-facet="<?= h(implode(' ', $tokens)) ?>"
         data-vp-time="<?= h($fmt($row['created'], 'YmdHi')) ?>"
         data-vp-text="<?= h($blob) ?>"
         <?= $row['renamed'] ? 'data-vp-audit-renamed' : '' ?>>

        <div class="vp-tl-time" style="line-height: 1.3;">
            <div style="font-size: 0.7rem;">
                <?= h($fmt($row['created'], 'j M Y')) ?>
            </div>
            <div style="font-size: 0.7rem;">
                <?= h($fmt($row['created'], 'H:i')) ?>
            </div>
        </div>

        <span class="vp-audit-act"
              style="<?= AuditActionMeta::style($row['action']) ?>"
              title="<?= h($meta['label']) ?>">
            <i class="<?= h($meta['icon']) ?>"></i>
        </span>

        <div class="vp-min-w-0">

            <div class="d-flex align-items-start gap-2">

            <div class="vp-min-w-0 flex-grow-1">
                <div class="small">
                    <?= h($title) ?>
                    <?php if ((int)$row['request_type'] === 1): ?>
                        <span class="badge bg-secondary-subtle
                                     text-secondary-emphasis border
                                     border-secondary-subtle ms-1"
                              title="<?= h(__(
                                  'Made through the API, not the web'
                                  . ' interface'
                              )) ?>"><?= __('API') ?></span>
                    <?php elseif ((int)$row['request_type'] === 2): ?>
                        <span class="badge bg-secondary-subtle
                                     text-secondary-emphasis border
                                     border-secondary-subtle ms-1"
                              title="<?= h(__(
                                  'Made from the command line'
                              )) ?>"><?= __('CLI') ?></span>
                    <?php endif; ?>
                </div>
                <?php if ($row['model_title'] !== null): ?>
                    <?php
                    /*
                     * **The record this row names, opened.** Phase 26
                     * §18.1 made that the rule for this page — a chip
                     * that names a record links to it — and this tab
                     * was built two phases before the rule and never
                     * got it, so every one of these sub-lines named a
                     * record and went nowhere.
                     *
                     * The targets are phase 26's, unchanged: an event
                     * report has its own page, and everything else is
                     * reached through the event that holds it, which
                     * is where MISP renders attributes, objects and
                     * proposals. Every audit row carries `event_id`,
                     * so the fallback always resolves — and where it
                     * somehow does not, the line renders exactly as it
                     * did before rather than as a dead anchor.
                     */
                    $recordUrl = null;
                    if ($row['model'] === 'EventReport'
                        && $row['model_id'] !== null
                    ) {
                        $recordUrl = $baseurl . '/eventReports/view/'
                            . (int)$row['model_id'];
                    } elseif ($row['event_id'] !== null) {
                        $recordUrl = $baseurl . '/events/view/'
                            . (int)$row['event_id'];
                    }
                    $recordLine = h($row['model'])
                        . ($row['model_id'] !== null
                            ? ' ' . h($row['model_id'])
                            : '')
                        . ' · ' . h($row['model_title']);
                    ?>
                    <div class="text-muted font-monospace"
                         style="font-size: 0.7rem;">
                        <?php if ($recordUrl !== null): ?>
                            <a href="<?= h($recordUrl) ?>"
                               class="text-reset"
                               title="<?= h(sprintf(
                                   __('Open %s'),
                                   $row['model'] === 'EventReport'
                                       ? __('this event report')
                                       : __('the event holding it')
                               )) ?>"><?= $recordLine ?></a>
                        <?php else: ?>
                            <?= $recordLine ?>
                        <?php endif; ?>
                    </div>
                <?php endif; ?>
                <?php if ($row['note'] !== null): ?>
                    <div class="vp-fact-line-sub">
                        <?= h($row['note']) ?>
                    </div>
                <?php endif; ?>
                <?php if ($row['renamed']): ?>
                    <?php
                    /*
                     * The one row that explains why this tab is scoped
                     * by attribute id. `AuditLogBehavior` files an
                     * edit under the title it produced, so this row
                     * sits in this value's history while naming
                     * another value on its left-hand side — and the
                     * three entries below it are filed under the old
                     * value entirely. A `model_title` match would have
                     * kept the wrong ones and lost these.
                     */
                    ?>
                    <div class="vp-fact-line vp-fact-line-warn mt-1">
                        <i class="fas fa-triangle-exclamation"></i>
                        <span>
                            <?= __(
                                'This occurrence used to hold a'
                                . ' different address. MISP files an'
                                . ' edit under the value it produced,'
                                . ' so this row — and only the rows'
                                . ' above it — belong to this value;'
                                . ' the entries below it are filed'
                                . ' under the old one. The tab finds'
                                . ' them because it is scoped by'
                                . ' attribute id, not by value.'
                            ) ?>
                        </span>
                    </div>
                <?php endif; ?>
            </div>

            <div class="text-end text-muted flex-shrink-0 vp-min-w-0"
                 style="font-size: 0.7rem; line-height: 1.3;
                        max-width: 11rem;">
                <div class="text-truncate<?= $row['actor'] === null
                    ? ' fst-italic'
                    : '' ?>"
                     <?= $row['actor'] === null
                         ? 'title="' . h(__(
                             'MISP does not hand you the user on an'
                             . ' entry from outside your organisation'
                         )) . '"'
                         : '' ?>>
                    <?= h($row['actor'] !== null
                        ? $row['actor']
                        : __('unnamed user')) ?>
                </div>
                <div class="text-truncate"><?= h($row['org']) ?></div>
            </div>

            <?php if (!empty($row['change'])): ?>
                <button type="button"
                        class="btn btn-sm btn-link p-0 flex-shrink-0
                               text-muted"
                        data-vp-audit-diff
                        aria-expanded="false"
                        title="<?= h(__('Show what changed')) ?>">
                    <i class="fas fa-chevron-down"></i>
                </button>
            <?php else: ?>
                <span class="flex-shrink-0" style="width: 1rem;"></span>
            <?php endif; ?>

        </div>

        <?php if (!empty($row['change'])): ?>
            <?php
            /*
             * From the row rather than `AuditLogsController::fullChange`,
             * whose `__applyAuditAcl` restricts a non-site-admin to their
             * own `user_id` and would 404 on most diffs on screen.
             */
            ?>
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
 * The action-mix bar for one occurrence.
 *
 * Segments follow the vocabulary order and not the counts, so two bars
 * a reader is comparing put the same action in the same place. It is
 * never re-proportioned under a filter: it describes the occurrence,
 * and redrawing it would make the filter look like history.
 *
 * @param array $mix
 * @param int $total
 * @return string
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
        $segments .= '<span style="'
            . AuditActionMeta::style($action)
            . ' --vp-audit-share: ' . $share . '%;"></span>';
        $legend[] = AuditActionMeta::label($action)
            . ' ' . $mix[$action];
    }
    return '<span class="vp-audit-mix" title="'
        . h(implode(' · ', $legend)) . '">' . $segments . '</span>';
};

/*
 * The rail's four groups. Order, heading and glyph belong here — only the
 * counts vary by value — and the notes are where the group says what its number
 * does not cover.
 */
$railGroups = array(
    array(
        'key' => 'action',
        'title' => __('Action'),
        'icon' => 'fas fa-bolt',
        'rows' => $facets['action'],
        'note' => h(__(
            'Counted against every action that can reach an attribute'
            . ' or its event, so a zero is a statement: nothing here'
            . ' was ever hard-deleted or restored.'
        )),
    ),
    array(
        'key' => 'model',
        'title' => __('Model'),
        'icon' => 'fas fa-cube',
        'rows' => $facets['model'],
        'note' => null,
    ),
    array(
        'key' => 'org',
        'title' => __('Organisation'),
        'icon' => 'fas fa-building',
        'rows' => $facets['org'],
        'note' => null,
    ),
    array(
        'key' => 'actor',
        'title' => __('Actor'),
        'icon' => 'fas fa-user',
        'rows' => $facets['actor'],
        'note' => h(__(
            'An entry from outside your organisation is filed under the'
            . ' organisation, because MISP does not hand you the user.'
            . ' A site admin sees names where you see these.'
        )),
    ),
);

/*
 * The window the panel was rendered for, and the log it was cut out
 * of. Null is the whole log, which the reader has to ask for.
 */
$window = $history['window'];
$span = $history['span'];
$allTime = $window === null;
$historyBase = $baseurl . '/values/viewHistory/' . $valueB64;

/*
 * How long the default window is, measured off the window itself rather
 * than written down here. The number belongs to whoever set it, and a
 * second copy of it in this template is a second thing to change.
 */
$windowDays = 1 + (int)round(
    (strtotime($history['default_window']['to'])
        - strtotime($history['default_window']['from'])) / 86400
);

/**
 * @param array $window
 * @return string
 */
$windowLabel = function ($window) use ($fmt) {
    /*
     * Non-breaking spaces inside each date. The panel header puts this
     * on a line it shares with the search box and the grouping control,
     * and a wrap between the day and the month reads as two separate
     * facts rather than one date.
     */
    $day = function ($at) use ($fmt) {
        return str_replace(
            ' ',
            "\xc2\xa0",
            $fmt($at . ' 00:00:00', 'j M Y')
        );
    };
    return sprintf(
        '%1$s → %2$s',
        $day($window['from']),
        $day($window['to'])
    );
};

/*
 * The corpus total is on screen exactly once, here. Every other number
 * on the tab — the rail's counts, the section headers, the pagers —
 * describes the period, which is what decision 7 buys by scoping the
 * rail: one place to look for *how much is there altogether*, and no
 * pair of numbers inviting a comparison nobody asked for.
 */
$headerLine = implode(' &nbsp;·&nbsp; ', array(
    sprintf(
        __('Showing %1$s of %2$s entries'),
        '<span data-vp-list-shown>' . h($history['shown']) . '</span>',
        h($history['entries'])
    ),
    h(sprintf(
        __n(
            '%1$d occurrence, %2$d event',
            '%1$d occurrences, %2$d events',
            $history['occurrences']
        ),
        $history['occurrences'],
        $history['events']
    )),
    $allTime
        ? h(__('all time'))
        : h($windowLabel($window)),
));

ob_start();
?>
    <div class="input-group input-group-sm" style="width: 13rem">
        <span class="input-group-text">
            <i class="fas fa-magnifying-glass"></i>
        </span>
        <input type="text" class="form-control"
               data-vp-filter-text
               aria-label="<?= __('Search the listed entries') ?>"
               placeholder="<?= h(__('Search entries')) ?>">
    </div>

    <?php
    /*
     * Regrouping moves the rendered rows between three sets of
     * sections and fetches nothing. By organisation files each entry
     * under the organisation that acted; by field, an edit under the
     * fields it changed and anything else under its kind of action.
     */
    $groupings = array(
        'occurrence' => __('By occurrence'),
        'org' => __('By organisation'),
        'field' => __('By field'),
    );
    ?>
    <div class="btn-group btn-group-sm" role="group"
         aria-label="<?= __('Grouping') ?>">
        <?php foreach ($groupings as $key => $label): ?>
            <button type="button"
                    class="btn btn-outline-secondary<?=
                        $key === 'occurrence' ? ' active' : '' ?>"
                    data-vp-audit-group="<?= h($key) ?>"
                    aria-pressed="<?=
                        $key === 'occurrence' ? 'true' : 'false' ?>">
                <?= h($label) ?>
            </button>
        <?php endforeach; ?>
    </div>

    <button type="button" class="btn btn-sm btn-outline-secondary"
            data-vp-audit-expand-all
            data-vp-audit-label-expand="<?= h(__('Expand all')) ?>"
            data-vp-audit-label-collapse="<?= h(__('Collapse all')) ?>">
        <span data-vp-audit-expand-label><?= __('Expand all') ?></span>
    </button>
<?php
$headerExtra = ob_get_clean();

/*
 * The period control's bounds are the log's, never the window's. Phase
 * 16 took them from the rendered rows, which was the same thing then
 * and is not now: an input that could only reach the month the reader
 * already landed on could not reach the rest of the log.
 *
 * What the chart is handed. The plan covers the whole log regardless
 * of the window, so activity outside the period is visible rather than
 * inferred — which is the point of drawing it at all — and it carries
 * every grain `AUDIT_RULE` permits, so the zoom needs no second
 * request (§13.1).
 */
$chartPayload = array(
    'chart' => $history['chart'],
    'window' => $window,
    'span' => $span,
);
?>

<div class="row" data-vp-list data-vp-audit
     data-vp-audit-base="<?= h($historyBase) ?>">

    <div class="col-lg-3">
        <div class="card shadow-sm mb-3 vp-panel"
             style="--vp-panel-color: <?= h($panelColour) ?>;">

            <?php
            ob_start();
            ?>
                <button type="button" class="btn btn-sm btn-outline-danger"
                        data-vp-facet-clear disabled>
                    <?= __('Clear all') ?>
                </button>
            <?php
            $railExtra = ob_get_clean();
            ?>

            <?= $this->element('Values/View/value_panel_header', array(
                'panelTitle' => __('Filters'),
                'panelIcon' => 'fas fa-filter',
                'panelColor' => $panelColour,
                'panelSub' => sprintf(
                    __('%1$s entries · %2$s filters set'),
                    '<span data-vp-facet-rows>'
                        . h($history['shown']) . '</span>',
                    '<span data-vp-facet-count-active>0</span>'
                ),
                'panelExtra' => $railExtra,
            )) ?>

            <div class="p-3">
                <div class="vp-facet-note">
                    <?= __(
                        'Every count below covers the period and nothing'
                        . ' outside it, so moving the period moves them.'
                        . ' They are also what you may read rather than'
                        . ' what the instance holds — a site admin sees'
                        . ' more rows here than you do. The log\'s own'
                        . ' total is in the panel header.'
                    ) ?>
                </div>
                <?php if ($span !== null): ?>
                    <div class="vp-facetgrp">
                        <div class="vp-subhead">
                            <i class="fas fa-clock me-1"></i>
                            <?= __('Period') ?>
                        </div>
                        <div class="vp-facet-note">
                            <?= h(sprintf(
                                __('The log runs %1$s to %2$s. Both'
                                    . ' bounds are inclusive, and either'
                                    . ' one alone is a filter.'),
                                $fmt($span['from'] . ' 00:00:00', 'j M Y'),
                                $fmt($span['to'] . ' 00:00:00', 'j M Y')
                            )) ?>
                        </div>

                        <?php
                        /*
                         * The chart and the two inputs are one control,
                         * not a chart above a control: the brush writes
                         * the inputs and fires their own `change`, so
                         * the window stays statable as two dates and
                         * the whole existing filter path runs unchanged.
                         * That is also why they are next to each other
                         * — a reader has to be able to see the gesture
                         * land somewhere.
                         */
                        ?>
                        <script type="application/json"
                                data-vp-audit-data><?=
                            json_encode($chartPayload) ?></script>

                        <div class="vp-audit-chart" data-vp-audit-chart>
                            <canvas id="vp-audit-activity" role="img"
                                    aria-label="<?= h(__(
                                        'Audit entries over the whole'
                                        . ' log. The zoom control below'
                                        . ' states the span on screen'
                                        . ' and what one bar covers.'
                                    )) ?>"></canvas>
                            <?php
                            /*
                             * Hidden until the chart it controls
                             * exists. A brush framing an empty canvas
                             * offers a gesture that cannot do anything,
                             * which is worse than offering none.
                             */
                            ?>
                            <?= $this->element(
                                'genericElementsBS5/brush',
                                ['hidden' => true]
                            ) ?>
                        </div>
                        <?php
                        /*
                         * The zoom's caption replaces the static pair
                         * of axis labels this chart used to carry.
                         * Those named the log's two ends, which stops
                         * being what the chart shows the moment it can
                         * be zoomed — and a caption that reads the
                         * drawn buckets' own titles cannot drift from
                         * the bars above it.
                         */
                        ?>
                        <?= $this->element('Values/View/value_zoom', array(
                            'zoomLabel' => __('Zoom the activity chart'),
                            'zoomAway' => __('the period is not in view'),
                            'zoomSelection' => __(
                                'Look inside the period'
                            ),
                            'grain' => array(
                                'day' => __('one bar a day'),
                                'week' => __('one bar a week'),
                                'month' => __('one bar a month'),
                            ),
                            'zoomNote' => __(
                                'Drag the chart to set the period; click'
                                . ' it to go back to the period the'
                                . ' panel was fetched for. The buttons'
                                . ' change what the chart shows and'
                                . ' leave the period alone.'
                            ),
                        )) ?>

                        <div class="vp-audit-period">
                            <label class="form-label"
                                   for="vp-audit-from"><?= __('From') ?></label>
                            <input type="datetime-local"
                                   class="form-control form-control-sm"
                                   id="vp-audit-from" data-vp-filter-from
                                   min="<?= h($fmt(
                                       $span['from'] . ' 00:00:00',
                                       'Y-m-d\TH:i'
                                   )) ?>"
                                   max="<?= h($fmt(
                                       $span['to'] . ' 23:59:00',
                                       'Y-m-d\TH:i'
                                   )) ?>">
                            <label class="form-label"
                                   for="vp-audit-to"><?= __('To') ?></label>
                            <input type="datetime-local"
                                   class="form-control form-control-sm"
                                   id="vp-audit-to" data-vp-filter-to
                                   min="<?= h($fmt(
                                       $span['from'] . ' 00:00:00',
                                       'Y-m-d\TH:i'
                                   )) ?>"
                                   max="<?= h($fmt(
                                       $span['to'] . ' 23:59:00',
                                       'Y-m-d\TH:i'
                                   )) ?>">
                        </div>

                        <?php
                        /*
                         * The one control on this tab that re-queries,
                         * and it says so. A window is what makes the
                         * panel bounded; asking for the whole log is a
                         * different request and gets a different
                         * fragment rather than a filter that reveals
                         * rows the page was never sent.
                         */
                        ?>
                        <div class="vp-audit-scope">
                            <?php if ($allTime || $history['capped']): ?>
                                <button type="button"
                                        class="vp-filter-clear"
                                        data-vp-audit-scope="">
                                    <i class="fas fa-compress me-1"></i>
                                    <?= h(sprintf(
                                        __('back to the last %d days'),
                                        $windowDays
                                    )) ?>
                                </button>
                            <?php else: ?>
                                <button type="button"
                                        class="vp-filter-clear"
                                        data-vp-audit-scope="all">
                                    <i class="fas fa-expand me-1"></i>
                                    <?= __('show all time') ?>
                                </button>
                            <?php endif; ?>
                        </div>
                    </div>
                <?php endif; ?>
                <?php foreach ($railGroups as $group): ?>
                    <?= $this->element(
                        'Values/View/value_facet_group',
                        array(
                            'key' => $group['key'],
                            'title' => $group['title'],
                            'icon' => $group['icon'],
                            'values' => $group['rows'],
                            'note' => $group['note'],
                        )
                    ) ?>
                <?php endforeach; ?>
            </div>

        </div>
    </div>

    <div class="col-lg-9">
        <div class="card shadow-sm mb-3 vp-panel"
             style="--vp-panel-color: <?= h($panelColour) ?>;">

            <?= $this->element('Values/View/value_panel_header', array(
                'panelTitle' => __('History'),
                'panelIcon' => $panelIcon,
                'panelColor' => $panelColour,
                'panelSub' => $headerLine,
                'panelExtra' => $headerExtra,
            )) ?>

            <?php
            /*
             * Directly under the header and not at the foot. This is
             * the one page in MISP where a reader can be misled into
             * thinking they are looking at the whole record, and the
             * sentence costs one line.
             *
             * The two numbers count the events holding a visible
             * occurrence, which is what
             * `AuditLogsController::__createEventIndexConditions`
             * actually branches on: every row for an event your
             * organisation created, and otherwise the event-level rows
             * plus the parts of it you may fetch.
             */
            ?>
            <div class="vp-acl-note vp-acl-note-band">
                <i class="fas fa-user-shield"></i>
                <span>
                    <?= __(
                        'This history is scoped to what you may read:'
                        . ' every entry on events your organisation'
                        . ' created, and on the others the event-level'
                        . ' entries plus the entries on occurrences you'
                        . ' may read. A site admin sees more rows here'
                        . ' than you do.'
                    ) ?>
                </span>
            </div>

            <?php
            /*
             * What is not a section, and why. Above the sections rather
             * than under them, because it is the sentence that stops
             * seventeen boxes from reading as seventeen copies of this
             * value.
             *
             * Two counts and two reasons, and phase 27 merged what
             * used to be three. An occurrence with no entry in this
             * period is reachable by moving the window; one the filters
             * emptied is reachable by clearing them. The third —
             * *nothing logged against it at all* — is gone with the
             * `silent` key: `27-history.md` §3.1 measured it at zero on
             * every value on this instance, because `AuditLogBehavior`
             * writes an `add` row when an attribute is created, and
             * telling the two apart costs a grouped read over every
             * occurrence to report a zero. Phase 16 dimmed all of them
             * to `opacity-50` and kept them on screen, which at 190
             * sections is the problem restated rather than fixed.
             */
            ?>
            <?php if ($history['outside'] > 0
                || $history['occurrences'] > 0
            ): ?>
                <div class="vp-acl-note vp-acl-note-band"
                     data-vp-audit-elided>
                    <i class="fas fa-list-ul"></i>
                    <span>
                        <?php if ($history['outside'] > 0): ?>
                            <?php
                            /*
                             * Two forms, because there are two
                             * reasons an occurrence has no section and
                             * only one of them is the period's. At all
                             * time there is no period to blame; and
                             * whenever the read hit the row cap, some
                             * of these occurrences *do* have entries
                             * inside the period and were simply cut —
                             * so naming the period there would be
                             * false, not merely unhelpful. The header
                             * states `Showing N of M entries` in both
                             * cases, which is where the cap is
                             * visible.
                             */
                            ?>
                            <?php if ($allTime || $history['capped']): ?>
                                <?= h(sprintf(
                                    __n(
                                        '%1$d of the %2$d occurrences'
                                        . ' you can read has no section'
                                        . ' here — its entries are'
                                        . ' older than the newest this'
                                        . ' panel returns.',
                                        '%1$d of the %2$d occurrences'
                                        . ' you can read have no'
                                        . ' section here — their'
                                        . ' entries are older than the'
                                        . ' newest this panel returns.',
                                        $history['outside']
                                    ),
                                    $history['outside'],
                                    $history['visible']
                                )) ?>
                            <?php else: ?>
                                <?= h(sprintf(
                                    __n(
                                        '%1$d of the %2$d occurrences'
                                        . ' you can read has no entry'
                                        . ' in %3$s, so it has no'
                                        . ' section here.',
                                        '%1$d of the %2$d occurrences'
                                        . ' you can read have no entry'
                                        . ' in %3$s, so they have no'
                                        . ' sections here.',
                                        $history['outside']
                                    ),
                                    $history['outside'],
                                    $history['visible'],
                                    $windowLabel($window)
                                )) ?>
                            <?php endif; ?>
                        <?php endif; ?>
                        <?php
                        /*
                         * Written by the browser as the reader narrows,
                         * and empty until they do. The period variant
                         * names the dates, because a section vanishing
                         * has to read as a filter narrowing and not as
                         * data going missing.
                         *
                         * **Both plural forms are sent, and the browser
                         * picks.** They used to be chosen here by
                         * `__n` against the *section total* while the
                         * browser substituted the *dropped* count, so
                         * any value with more than one section and one
                         * dropped section read `1 of the sections
                         * below have no entry` — visible on `8.8.8.8`
                         * from the moment the tab went live. The
                         * server cannot know the number: it is
                         * whatever the reader's filter leaves.
                         */
                        ?>
                        <span class="d-none" data-vp-audit-dropped
                              data-vp-audit-drop-period-one="<?= h(__(
                                  '%1$s of the sections below has no'
                                      . ' entry between %2$s and %3$s.'
                              )) ?>"
                              data-vp-audit-drop-period-many="<?= h(__(
                                  '%1$s of the sections below have no'
                                      . ' entry between %2$s and %3$s.'
                              )) ?>"
                              data-vp-audit-drop-plain-one="<?= h(__(
                                  '%1$s of the sections below has no'
                                      . ' entry matching these filters.'
                              )) ?>"
                              data-vp-audit-drop-plain-many="<?= h(__(
                                  '%1$s of the sections below have no'
                                      . ' entry matching these filters.'
                              )) ?>"></span>
                    </span>
                </div>
            <?php endif; ?>

            <?php if ($history['shown'] === 0 && !$allTime): ?>
                <?php
                /*
                 * The window is empty and the log is not. Its own state
                 * rather than the filter one below, because no filter
                 * produced it: the panel was fetched for a period the
                 * value has no entries in, and "no entry matches these
                 * filters" over an untouched control would be a false
                 * claim about a control the reader never used.
                 *
                 * What it has to say is where the entries are, not that
                 * there are none. A tab that renders nothing here is
                 * indistinguishable from a value with no history at
                 * all, and those are the two states §11.3 exists to
                 * keep apart.
                 */
                $quiet = $span === null
                    ? null
                    : (int)round(
                        (strtotime($window['from'] . ' 00:00:00')
                            - strtotime($span['to'] . ' 00:00:00'))
                        / 86400
                    );
                ?>
                <div class="vp-audit-quiet">
                    <i class="fas fa-calendar-xmark"></i>
                    <div>
                        <div class="fw-semibold">
                            <?= h(sprintf(
                                __(
                                    'Nothing was logged against this'
                                    . ' value between %1$s and %2$s.'
                                ),
                                $fmt(
                                    $window['from'] . ' 00:00:00',
                                    'j M Y'
                                ),
                                $fmt($window['to'] . ' 00:00:00', 'j M Y')
                            )) ?>
                        </div>
                        <?php if ($span !== null): ?>
                            <div class="vp-audit-quiet-note">
                                <?= h(sprintf(
                                    __n(
                                        'Its log holds %1$d entry, the'
                                        . ' most recent on %2$s — %3$s'
                                        . ' before this period begins.',
                                        'Its log holds %1$d entries, the'
                                        . ' most recent on %2$s — %3$s'
                                        . ' before this period begins.',
                                        $history['entries']
                                    ),
                                    $history['entries'],
                                    $fmt(
                                        $span['to'] . ' 00:00:00',
                                        'j M Y'
                                    ),
                                    sprintf(
                                        __n('%d day', '%d days', $quiet),
                                        $quiet
                                    )
                                )) ?>
                            </div>
                            <div class="vp-audit-quiet-note">
                                <?= h(__(
                                    'The chart in the rail is drawn over'
                                    . ' the whole log, so where those'
                                    . ' entries are is on it — the'
                                    . ' window is simply past their'
                                    . ' right-hand end.'
                                )) ?>
                            </div>
                        <?php endif; ?>
                        <button type="button"
                                class="btn btn-sm btn-outline-secondary
                                       mt-2"
                                data-vp-audit-scope="all">
                            <i class="fas fa-expand me-1"></i>
                            <?= __('show all time') ?>
                        </button>
                    </div>
                </div>
            <?php endif; ?>

            <div data-vp-list-rows>

                <div data-vp-audit-grouping="occurrence">
                <?php foreach ($history['groups'] as $index => $group): ?>
                    <?php
                    $sectionId = 'vp-audit-' . (int)$group['attribute_id'];
                    // The first section is open, the rest closed: a tab
                    // that opens six of these opens with nine hundred
                    // pixels of rows and no shape.
                    $open = $index === 0;
                    ?>
                    <div class="border-bottom"
                         data-vp-audit-section
                         data-vp-audit-total="<?= h($group['count']) ?>">

                        <div class="d-flex align-items-center gap-2 gap-lg-3
                                    p-2 px-3 flex-wrap">

                            <button type="button"
                                    class="btn btn-sm btn-link
                                           text-decoration-none p-0
                                           text-body d-flex
                                           align-items-center gap-2"
                                    data-vp-audit-toggle
                                    aria-expanded="<?= $open
                                        ? 'true'
                                        : 'false' ?>"
                                    aria-controls="<?= h($sectionId) ?>">
                                <i class="fas fa-chevron-<?= $open
                                    ? 'down'
                                    : 'right' ?>"
                                   data-vp-audit-chevron></i>
                                <span class="font-monospace small">
                                    <?= h($group['attribute_id']) ?>
                                </span>
                            </button>

                            <div class="vp-min-w-0 flex-grow-1">
                                <div class="small text-truncate">
                                    <?= h($group['event_info']) ?>
                                    <?php if ($group['deleted']): ?>
                                        <?= $deletedBadge() ?>
                                    <?php endif; ?>
                                </div>
                                <div class="text-muted"
                                     style="font-size: 0.7rem;">
                                    <?= h(sprintf(
                                        __('event %1$s · %2$s'),
                                        $group['event_id'],
                                        $group['org']
                                    )) ?>
                                </div>
                            </div>

                            <div class="flex-shrink-0"
                                 style="width: 8.5rem;">
                                <?= $renderMix(
                                    $group['mix'],
                                    $group['count']
                                ) ?>
                                <?php
                                /*
                                 * The count is the window's, because
                                 * the rows under it are. The whole-log
                                 * number is a tooltip rather than a
                                 * second figure on the line: three
                                 * numbers in eight and a half rems is
                                 * how a header stops being readable.
                                 */
                                ?>
                                <div class="text-muted"
                                     style="font-size: 0.7rem;"
                                     <?= $group['total'] > $group['count']
                                         ? 'title="' . h(sprintf(
                                             __n(
                                                 '%d entry on this'
                                                 . ' occurrence over the'
                                                 . ' whole log',
                                                 '%d entries on this'
                                                 . ' occurrence over the'
                                                 . ' whole log',
                                                 $group['total']
                                             ),
                                             $group['total']
                                         )) . '"'
                                         : '' ?>
                                     data-vp-audit-count
                                     data-vp-audit-plain="<?= h(sprintf(
                                         __n(
                                             '%d entry',
                                             '%d entries',
                                             $group['count']
                                         ),
                                         $group['count']
                                     )) ?>"
                                     data-vp-audit-tpl="<?= h(__n(
                                         '%1$s of %2$s entry',
                                         '%1$s of %2$s entries',
                                         $group['count']
                                     )) ?>"><?= h(sprintf(
                                         __n(
                                             '%d entry',
                                             '%d entries',
                                             $group['count']
                                         ),
                                         $group['count']
                                     )) ?></div>
                            </div>

                            <div class="text-muted text-end flex-shrink-0"
                                 style="width: 6rem; font-size: 0.7rem;">
                                <?php if ($group['last'] !== null): ?>
                                    <?= h($fmt($group['last'], 'j M Y')) ?>
                                <?php else: ?>
                                    <span class="fst-italic">
                                        <?= __('nothing logged') ?>
                                    </span>
                                <?php endif; ?>
                            </div>

                            <a href="<?= $baseurl ?>/events/view/<?=
                                h($group['event_id']) ?>"
                               class="flex-shrink-0 small"
                               title="<?= h(__(
                                   'Open the event holding this'
                                   . ' occurrence'
                               )) ?>">
                                <i class="fas fa-arrow-up-right-from-square">
                                </i>
                            </a>

                        </div>

                        <div id="<?= h($sectionId) ?>"
                             data-vp-audit-body
                             class="<?= $open ? '' : 'd-none' ?>">
                            <?php foreach ($group['entries'] as $row): ?>
                                <?= $renderRow($row, $sectionId) ?>
                            <?php endforeach; ?>

                            <?php if ($group['count'] > $pageSize): ?>
                                <div class="px-3 py-2 border-top"
                                     data-vp-audit-pagerhost>
                                    <?= $this->element(
                                        'Values/View/value_pager',
                                        array(
                                            'size' => $pageSize,
                                            'shown' => $group['count'],
                                            'total' => $group['count'],
                                            'noun' => array(
                                                'one' => __('entry'),
                                                'many' => __('entries'),
                                            ),
                                        )
                                    ) ?>
                                </div>
                            <?php endif; ?>
                        </div>

                    </div>
                <?php endforeach; ?>

                <?php if ($history['occurrences'] > $sectionSize): ?>
                    <?php
                    /*
                     * A pager over sections, which can only sit beside
                     * the per-section entry pagers because phase 18
                     * §10.2 scoped a nested list's controls to its own
                     * rows. Before that, one of the two would have been
                     * paging the other's.
                     *
                     * `total` is the sections this window holds and not
                     * the value's occurrence count: what the window
                     * left out is the sentence above, where it can name
                     * a reason, and repeating it as a bare number here
                     * would invite the reader to read the difference as
                     * sections they could page to.
                     */
                    ?>
                    <div class="px-3 py-2 border-top"
                         data-vp-audit-sectionpager>
                        <?= $this->element(
                            'Values/View/value_pager',
                            array(
                                'size' => $sectionSize,
                                'shown' => $history['occurrences'],
                                'total' => $history['occurrences'],
                                'noun' => array(
                                    'one' => __('occurrence'),
                                    'many' => __('occurrences'),
                                ),
                            )
                        ) ?>
                    </div>
                <?php endif; ?>

                <?php if (!empty($history['event_entries'])): ?>
                    <?php
                    /*
                     * Below a rule and outside the groups, because a
                     * publication belongs to the value's story and to
                     * none of its copies. Repeating these ten inside
                     * six sections would read as sixty things having
                     * happened; dropping them would lose every
                     * publication this value has.
                     *
                     * Pinned: the section pager above pages occurrences,
                     * and this is not one of them. A reader who paged
                     * the publications off the bottom of page one would
                     * have to guess which page they went to.
                     */
                    $eventTotal = count($history['event_entries']);
                    ?>
                    <div class="border-top border-2"
                         data-vp-audit-section
                         data-vp-audit-pinned
                         data-vp-audit-total="<?= h($eventTotal) ?>">

                        <div class="d-flex align-items-center gap-3
                                    p-2 px-3 flex-wrap">
                            <button type="button"
                                    class="btn btn-sm btn-link
                                           text-decoration-none p-0
                                           text-body d-flex
                                           align-items-center gap-2"
                                    data-vp-audit-toggle
                                    aria-expanded="false"
                                    aria-controls="vp-audit-events">
                                <i class="fas fa-chevron-right"
                                   data-vp-audit-chevron></i>
                                <span class="small fw-bold">
                                    <?= __('Not tied to one occurrence') ?>
                                </span>
                            </button>
                            <div class="vp-min-w-0 flex-grow-1
                                        vp-fact-line-sub">
                                <?php
                                /*
                                 * Was *Event-level actions*, and was
                                 * accurate while the only rows here
                                 * were the event's own. Phase 27 added
                                 * three more models to the scope — the
                                 * containing object's edits, proposals
                                 * and event reports — and none of them
                                 * is event-level either. What the four
                                 * share is the thing the section is
                                 * for: they happened to this value and
                                 * to no single copy of it.
                                 */
                                ?>
                                <?= __(
                                    'Publications, event tags, edits to'
                                    . ' the objects this value sits in,'
                                    . ' proposals and event reports.'
                                    . ' Each belongs to this value and'
                                    . ' to no single occurrence of it,'
                                    . ' so each is counted once here'
                                    . ' rather than repeated in every'
                                    . ' section above.'
                                ) ?>
                            </div>
                            <div class="text-muted flex-shrink-0"
                                 style="font-size: 0.7rem;"
                                 data-vp-audit-count
                                 data-vp-audit-plain="<?= h(sprintf(
                                     __n(
                                         '%d entry',
                                         '%d entries',
                                         $eventTotal
                                     ),
                                     $eventTotal
                                 )) ?>"
                                 data-vp-audit-tpl="<?= h(__n(
                                     '%1$s of %2$s entry',
                                     '%1$s of %2$s entries',
                                     $eventTotal
                                 )) ?>"><?= h(sprintf(
                                     __n(
                                         '%d entry',
                                         '%d entries',
                                         $eventTotal
                                     ),
                                     $eventTotal
                                 )) ?></div>
                        </div>

                        <div id="vp-audit-events" data-vp-audit-body
                             class="d-none">
                            <?php foreach (
                                $history['event_entries'] as $row
                            ): ?>
                                <?= $renderRow($row, 'vp-audit-events') ?>
                            <?php endforeach; ?>

                            <?php if ($eventTotal > $pageSize): ?>
                                <div class="px-3 py-2 border-top"
                                     data-vp-audit-pagerhost>
                                    <?= $this->element(
                                        'Values/View/value_pager',
                                        array(
                                            'size' => $pageSize,
                                            'shown' => $eventTotal,
                                            'total' => $eventTotal,
                                            'noun' => array(
                                                'one' => __('entry'),
                                                'many' => __('entries'),
                                            ),
                                        )
                                    ) ?>
                                </div>
                            <?php endif; ?>
                        </div>

                    </div>
                <?php endif; ?>
                </div>

                <?php foreach (array('org', 'field') as $grouping): ?>
                    <?= $this->element(
                        'Values/View/value_history_regroup',
                        array(
                            'grouping' => $grouping,
                            'sections' => $grouping === 'org'
                                ? $history['regroups']['orgs']
                                : $history['regroups']['fields'],
                            'bodyId' => $grouping === 'org'
                                ? $orgBody
                                : $fieldBody,
                            'renderMix' => $renderMix,
                            'fmt' => $fmt,
                            'pageSize' => $pageSize,
                            'sectionSize' => $sectionSize,
                        )
                    ) ?>
                <?php endforeach; ?>

            </div>

            <?php
            /*
             * Fires only where a filter produced the emptiness
             * (`00-shared.md` §5.1). A panel that was empty to begin
             * with has its own state above, and "no entry matches your
             * filter" over a value with no entries is a different and
             * false claim.
             */
            ?>
            <div class="vp-empty d-none" data-vp-list-empty>
                <i class="fas fa-filter"></i>
                <span>
                    <?= __(
                        'No entry matches these filters, so no section'
                        . ' is listed. How many occurrences this value'
                        . ' has is unchanged and is stated above the'
                        . ' sections; only what is drawn as a box'
                        . ' follows the filters.'
                    ) ?>
                </span>
            </div>


        </div>
    </div>

</div>
<?php endif; ?>
