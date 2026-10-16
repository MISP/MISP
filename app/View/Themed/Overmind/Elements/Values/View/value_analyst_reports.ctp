<?php
/**
 * The event reports written about the events this value sits in.
 *
 * The third panel on the Analyst tab, and the one that is a list rather
 * than an argument. `value-intelligence-coverage.md` §4.5 places reports
 * here — narrative analyst content about the value's context, beside
 * the notes and opinions — and they are a panel of their own rather
 * than more thread items because a report is a document, not a turn in
 * a conversation: dropped between two one-line notes it buries both.
 *
 * **Every row is about an event and says so.** Analyst data attaches to
 * a uuid and a report attaches to an event; nothing attaches to a
 * value. What this panel can state honestly is *a report was written
 * about an event this value is in*, which is the same sentence the
 * thread's event-level items carry.
 *
 * **The audience is resolved, not reported.** A report's own
 * `distribution` is `5` — *inherit* — on every report nobody narrowed,
 * because that is the shipped default, so a badge printing the column
 * says nothing on almost every row. The model resolves the report →
 * event chain through the same helper an occurrence's three links go
 * through, and the badge names the level the reader is actually asking
 * about.
 *
 * **The extract is the head of the report, not a summary.** MISP has no
 * summary of a report and this page will not write one — an abstract
 * the page invented would be the page's claim about somebody's
 * document. The first few hundred characters are the document's own
 * opening, marked as truncated, with the full length beside it.
 *
 * Lazily loaded into `.ajax-tab-content` from
 * ValuesController::viewAnalystReports.
 *
 * @var array $valueIntelligence
 */
App::uses('ValueStatsTool', 'Tools/ValueIntelligence');

$reports = $valueIntelligence['analyst_reports'];
$rows = $reports['rows'];

/**
 * A report's opening, as text.
 *
 * The body is markdown and this is a four-line extract, so the markup
 * is stripped rather than rendered: half a rendered heading and an
 * orphaned list bullet read as a broken document, where a paragraph of
 * plain prose reads as the start of one. Escaped on the way out like
 * everything else.
 *
 * @param string $head
 * @return string
 */
$extract = function ($head) {
    $text = preg_replace('/```.*?```/s', ' ', $head);
    /*
     * MISP's own element references first — `@![attribute](uuid)` and
     * its object and tag siblings. They render as a card in the report
     * and as a uuid in an extract, which is the one thing an opening
     * paragraph must not be made of.
     */
    $text = preg_replace('/@!?\[[^\]]*\]\([^)]*\)/', '', $text);
    // Then images, which are a filename and a path, and then links,
    // which keep the words and drop the URL.
    $text = preg_replace('/!\[[^\]]*\]\([^)]*\)/', '', $text);
    $text = preg_replace('/\[([^\]]*)\]\([^)]*\)/', '$1', $text);
    $text = preg_replace('/^\s*[#>]+\s*/m', '', $text);
    $text = preg_replace('/^\s*[-*]\s+/m', '', $text);
    // `*` and backticks, but never `_`: a report full of snake_case
    // identifiers is more common than one using underscore emphasis.
    $text = preg_replace('/[`*]+/', '', $text);
    // The editor escapes punctuation on save, so the stored bytes read
    // `RFC 7231\)` and an extract that kept the backslash would be
    // showing the reader the storage format.
    $text = preg_replace('/\\\\([\\\\`*_{}\[\]()#+\-.!])/', '$1', $text);
    $text = trim(preg_replace('/\s+/', ' ', $text));
    return $text;
};

/**
 * A level as its words and its glyph.
 *
 * The words come from `ValueStatsTool::levelLabel()` and not from a
 * table here: the Timeline lane names the same five audiences in a
 * sentence, and two spellings of *Connected communities* on one page is
 * the kind of drift nothing catches. The glyph stays local — it is this
 * panel's badge and no other caller wants one.
 *
 * `$level` is `null` where the report defers and its event did not
 * resolve, which is the one case this panel cannot state a level for.
 * Unreachable in practice: the report fetch already required the event
 * to pass the same ACL.
 *
 * @param int|null $level
 * @param string|null $sharingGroup
 * @return array label, icon
 */
$distribution = function ($level, $sharingGroup) {
    $label = ValueStatsTool::levelLabel($level, $sharingGroup);
    if ($level === null) {
        return array($label, 'fas fa-share-nodes');
    }
    if ((int)$level === 4) {
        return array($label,
            'misp-icon misp-icon-sharing-group misp-simple');
    }
    return array($label,
        (int)$level === 0 ? 'fas fa-lock' : 'fas fa-share-nodes');
};

/**
 * The chain behind the badge — "Report: Inherit event → Event: This
 * community only".
 *
 * The badge names one level and the reader's next question is whose it
 * is, which is the same question the occurrence table's distribution
 * cell answers the same way. A report whose event did not resolve is a
 * one-link chain and says so by having nothing after the arrow.
 *
 * @param array $row
 * @return string
 */
$chain = function ($row) use ($distribution) {
    list($own) = $distribution($row['distribution'],
        $row['sharing_group']);
    $links = array(sprintf('%s: %s', __('Report'), $own));
    if ($row['event']['distribution'] !== null) {
        list($their) = $distribution($row['event']['distribution'],
            $row['event']['sharing_group']);
        $links[] = sprintf('%s: %s', __('Event'), $their);
    }
    $title = implode(' → ', $links);
    if ($row['audience']['intersects']) {
        /*
         * A sharing group alongside another constraint means the real
         * audience is an intersection, and no single level says that.
         * The badge shows the tightest level it can name; this says the
         * real audience is narrower still.
         */
        $title .= ' · ' . __(
            'Both apply, so the real audience is narrower than any one'
            . ' of them'
        );
    }
    return $title;
};

/*
 * Nothing to count is a state. `0 reports across 20 events` is a
 * sentence about a panel with no rows, and it is the kind of sentence
 * that makes a working page look broken.
 */
$subtitle = empty($rows)
    ? h(__('No event report on any event this value appears in'))
    : implode(' &nbsp;·&nbsp; ', array_filter(array(
        h(sprintf(
            __('%1$s on %2$s'),
            __n('%s report', '%s reports', $reports['total'],
                $reports['total']),
            __n('%s event', '%s events', $reports['events'],
                $reports['events'])
        )),
        $reports['withdrawn'] > 0
            ? h(sprintf(
                __n(
                    '%s withdrawn',
                    '%s withdrawn',
                    $reports['withdrawn']
                ),
                $reports['withdrawn']
            ))
            : null,
        h(__('newest change first')),
    )));
?>
<div class="card shadow-sm mb-3 vp-panel vp-dense"
     style="--vp-panel-color: var(--analystData);"
     data-vp-analyst-reports>

    <?= $this->element('Values/View/value_panel_header', array(
        'panelTitle' => __('Event reports'),
        'panelIcon' => 'fas fa-file-lines',
        'panelColor' => 'var(--analystData)',
        'panelSub' => $subtitle,
    )) ?>

    <?php if (empty($rows)): ?>
        <div class="vp-empty">
            <i class="fas fa-file-lines"></i>
            <span><?= __(
                'Nobody has written an event report on an event this'
                . ' value appears in.'
            ) ?></span>
        </div>
    <?php else: ?>
        <div class="p-3">
            <?php foreach ($rows as $row):
                /*
                 * The resolved level, not the report's own column —
                 * which is `Inherit event` on every report nobody
                 * narrowed, and that is the shipped default. The model
                 * resolves the report → event chain the same way an
                 * occurrence's three links are resolved, so the two
                 * panels cannot disagree about one event's audience.
                 */
                $audience = $row['audience'];
                list($distLabel, $distIcon) = $audience['level'] === null
                    ? $distribution(null, null)
                    : $distribution(
                        $audience['level'],
                        $audience['sharing_group_name'] === null
                            ? $row['sharing_group']
                            : $audience['sharing_group_name']
                    );
                $body = $extract($row['head']);
                $truncated = $row['length'] > mb_strlen($row['head']);
                ?>
                <div class="vpa-report<?=
                    $row['withdrawn'] ? ' vpa-report-gone' : '' ?>">

                    <div class="d-flex align-items-center gap-2 flex-wrap
                                mb-1">
                        <a class="vpa-report-name"
                           href="<?= h($baseurl) ?>/eventReports/view/<?=
                               (int)$row['id'] ?>"
                           title="<?= h(__('Open the report')) ?>"><?=
                            h($row['name'] === '' || $row['name'] === null
                                ? __('(untitled report)')
                                : $row['name'])
                        ?></a>

                        <?php if ($row['withdrawn']): ?>
                            <span class="badge bg-secondary-subtle
                                         text-secondary-emphasis border
                                         border-secondary-subtle
                                         fw-semibold"
                                  title="<?= h(__(
                                      'Soft-deleted. A withdrawn report'
                                      . ' saves only its deleted column,'
                                      . ' so its date is still the day'
                                      . ' its content last changed.'
                                  )) ?>"><?= __('Withdrawn') ?></span>
                        <?php endif; ?>

                        <?php
                        /*
                         * The event opens, on its Reports tab. It named
                         * `#177 Event created via the API as an example`
                         * and left the reader to find it, which is the
                         * page holding an address rather than offering
                         * it — the same rule the thread's chips and the
                         * Timeline's entries already follow.
                         */
                        ?>
                        <a class="ms-auto vpa-chip vpa-chip-link"
                           href="<?= h($baseurl) ?>/events/view/<?=
                               (int)$row['event']['id'] ?>#tab-reports"
                           title="<?= h(__(
                               'A report is written about an event,'
                               . ' never about a value — this one is on'
                               . ' an event this value appears in. Opens'
                               . ' the event, on its Reports tab.'
                           )) ?>">
                            <span class="misp-icon misp-icon-event
                                         misp-simple"></span>
                            <?= h('#' . $row['event']['id']) ?>
                            <?php if (!empty($row['event']['info'])): ?>
                                <span class="vpa-chip-sep vp-min-w-0
                                             text-truncate"><?=
                                    h($row['event']['info'])
                                ?></span>
                            <?php endif; ?>
                            <i class="fas fa-arrow-up-right-from-square"
                               aria-hidden="true"></i>
                        </a>
                    </div>

                    <?php if ($body !== ''): ?>
                        <div class="vpa-report-extract"><?= h($body)
                            ?><?php if ($truncated): ?><span
                                class="vpa-report-more"
                                title="<?= h(sprintf(
                                    __('The report is %s characters long;'
                                        . ' this is its opening.'),
                                    $row['length']
                                )) ?>">&nbsp;<?= __('…') ?></span>
                            <?php endif; ?></div>
                    <?php endif; ?>

                    <div class="vp-analyst-meta d-flex align-items-center
                                flex-wrap gap-2">
                        <span>
                            <span class="misp-icon
                                         misp-icon-organisation
                                         misp-simple me-1"></span>
                            <?php if (empty($row['org_id'])): ?>
                                <?= h($row['org']) ?>
                            <?php else: ?>
                                <a class="vpa-orglink"
                                   href="<?= h($baseurl) ?>/organisations/view/<?=
                                       (int)$row['org_id'] ?>"><?=
                                    h($row['org'])
                                ?></a>
                            <?php endif; ?>
                            <?php if ($row['at'] !== null): ?>
                                &nbsp;&middot;&nbsp;
                                <i class="fas fa-clock me-1"></i>
                                <span title="<?= h(__(
                                    'When the report last changed.'
                                    . ' event_reports has no creation'
                                    . ' date — its one timestamp is'
                                    . ' rewritten on every edit.'
                                )) ?>"><?= h($row['at']) ?>
                                    <?= __('(last changed)') ?></span>
                            <?php endif; ?>
                        </span>
                        <span class="badge bg-body-tertiary
                                     text-body-secondary border fw-normal"
                              title="<?= h($chain($row)) ?>">
                            <?php if ($distIcon === 'fas fa-lock'
                                || $distIcon === 'fas fa-share-nodes'): ?>
                                <i class="<?= $distIcon ?> me-1"></i>
                            <?php else: ?>
                                <span class="<?= $distIcon ?> me-1"></span>
                            <?php endif; ?>
                            <?= h($distLabel) ?>
                            <?php
                            /*
                             * Whose level this is. The badge would
                             * otherwise read as the report's own claim,
                             * and on a report at the shipped default it
                             * is the event's — not something anybody
                             * set on the report and not editable there.
                             */
                            ?>
                            <?php if ($audience['source'] === 'event'): ?>
                                <span class="vpa-chip-sep"><?=
                                    __('from the event')
                                ?></span>
                            <?php endif; ?>
                            <?php if ($audience['intersects']): ?>
                                <i class="fas fa-link ms-1
                                          text-warning-emphasis"
                                   aria-hidden="true"></i>
                            <?php endif; ?>
                        </span>
                        <span class="vpa-chip"><?= h(sprintf(
                            __n(
                                '%s character',
                                '%s characters',
                                $row['length']
                            ),
                            $row['length']
                        )) ?></span>
                    </div>
                </div>
            <?php endforeach; ?>

            <?php if (!empty($reports['capped'])): ?>
                <p class="vp-aside-note"><?= h(sprintf(
                    __('Showing the %1$s most recently changed of %2$s.'
                        . ' There is no page control here: the rows come'
                        . ' from every event this value appears in, and'
                        . ' a value in thousands of them would be'
                        . ' paginating a list nobody asked for.'),
                    count($rows),
                    $reports['total']
                )) ?></p>
            <?php endif; ?>
        </div>
    <?php endif; ?>

    <?php if (!empty($reports['occurrence_capped'])): ?>
        <?php
        /*
         * Outside the empty branch on purpose. A value past the
         * occurrence cap with no report on the events this read reached
         * renders *nobody has written one* over a slice of its events,
         * which is the one arrangement where the empty state is a
         * false statement rather than a true one.
         */
        ?>
        <p class="vp-aside-note"><?= h(sprintf(
            __('This value has more occurrences than one read takes, so'
                . ' this list covers the %s events its most recent'
                . ' occurrences sit in. A report on an older event is'
                . ' not listed.'),
            $reports['events']
        )) ?></p>
    <?php endif; ?>

</div>
