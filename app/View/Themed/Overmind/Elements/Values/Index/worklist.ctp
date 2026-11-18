<?php
/**
 * A pasted list, as the rows to work.
 *
 * `02b-proposal-c.html`'s worklist. Phase 4 built the rows and what the
 * parse did to get to them; phase 5 gives them their assessments and,
 * with them, the machine C is for — the progress, a mark per row, the
 * *left to do* filters, the worst-first sort, the compact table view and
 * the line saying where the marks live, all on the count line over the
 * table, as the other index pages put their count and their pager.
 *
 * **That chrome arrives with its subject and not before.** Until there
 * were decisions to work, a progress bar would have stood still, a filter
 * would never have subtracted a row and a second view would have drawn
 * the same thing at a different size — so phase 4 shipped none of it.
 * It is drawn now, and only for a reader whose browser can fill the
 * rows: with no script no assessment ever arrives, so `.is-live` gates
 * every control on the thing that makes them mean anything, and what
 * is left is exactly the list phase 4 shipped.
 *
 * **The rows are the reader's own strings** — a table whose rows are
 * not the strings that were pasted is a table they cannot check
 * (§5) — and the links, and the assessments, are the instance's. Those
 * are two different spellings for a value MISP lowercased on the way
 * in, and both matter: the reader checks the row against their report,
 * and the assessment has to be of a value somebody holds, or the row
 * would disagree with the profile page it links to. What the read did
 * is counted in the provenance line rather than marked per row.
 *
 * @var array $triage `rows`, `recased`, `collapsed` from
 *                    `ValueIntelligence::forTriage`, and the parser's
 *                    `report`
 */
App::uses('ValueUrlTool', 'Tools/ValueIntelligence');
App::uses('ValueInputTool', 'Tools/ValueIntelligence');

$report = $triage['report'];
$rows = $triage['rows'];
// False when the reader's analyst profile switches the assessment off.
$showsAssessment = $showsAssessment ?? true;

/*
 * The tape and its legend are a picture of a batch's progress, and
 * below eight rows the picture says less than the rows themselves do.
 * The prototype's threshold, kept.
 */
$batched = count($rows) >= 8;

/*
 * What the parse did, as a sentence a reader can check against their
 * own paste. Only the clauses that happened are said: a list nothing
 * was done to gets the count and a full stop, which is the common
 * case and the one that should read shortest.
 */
$did = array();
if ($report[ValueInputTool::REFANGED]) {
    $did[] = sprintf(__('%d refanged'),
        $report[ValueInputTool::REFANGED]);
}
if ($report[ValueInputTool::UNQUOTED]) {
    $did[] = sprintf(__('%d stripped of quotes'),
        $report[ValueInputTool::UNQUOTED]);
}
if ($report['composites']) {
    $did[] = sprintf(__n('%d composite value split in two',
        '%d composite values split in two', $report['composites']),
        $report['composites']);
}
if ($report['duplicates']) {
    $did[] = sprintf(__n('%d duplicate removed',
        '%d duplicates removed', $report['duplicates']),
        $report['duplicates']);
}
if ($triage['collapsed']) {
    $did[] = sprintf(__('%d merged with a differently cased duplicate'),
        $triage['collapsed']);
}
if ($triage['recased']) {
    $did[] = sprintf(__('%d matched to the casing stored in MISP'),
        $triage['recased']);
}
if ($report['empty']) {
    /*
     * Not *blank lines*: a blank line never reaches this count, since
     * the field split drops it before anything is normalised. What is
     * counted here is a line that looked like a value and left
     * nothing — a stray pair of quotes, a lone zero-width space off a
     * web page — which is worth saying precisely because the reader
     * cannot see it in their own paste.
     */
    $did[] = sprintf(__('%d empty after cleanup'), $report['empty']);
}

/*
 * The lead names the unit the paste chose, because that is the rule
 * a reader most needs to see having run: a line-per-value paste is
 * unsurprising, and a single line split on its commas is the one
 * reading this box makes that the reader might not have meant.
 */
$extracted = isset($report['mode'])
    && $report['mode'] === ValueInputTool::MODE_EXTRACT;
$byCommas = !$extracted
    && $report['separator'] === ValueInputTool::BY_COMMAS;
if ($extracted) {
    /*
     * The extraction's lead names both numbers, because the gap
     * between them is the whole of what the reader agreed to: text
     * went in and a shortlist came out, and how much text produced
     * how little is the first thing worth knowing about it.
     */
    $lead = sprintf(__n('%1$d lines of text, %2$d value found.',
        '%1$d lines of text, %2$d values found.', count($rows)),
        $report['lines'], count($rows));
} elseif ($byCommas) {
    $lead = sprintf(__n('One line, split on its %1$d comma, became'
        . ' %2$d row.',
        'One line, split on its %1$d commas, became %2$d rows.',
        count($rows)), max(0, $report['fields'] - 1), count($rows));
} else {
    $lead = sprintf(__n('%1$d line became %2$d row.',
        '%1$d lines became %2$d rows.', count($rows)),
        $report['lines'], count($rows));
}

/*
 * **The offer, both ways round** (§11.3). An extraction always carries
 * a way back to the reader's own lines, because the extractor cannot
 * type about half of what an instance holds and a reader whose `mutex`
 * vanished has no other way to say *no, those were my values*. A line
 * reading offers the other direction when the rows look like prose —
 * the same shape as the comma offer below, and for the same reason
 * given there: only the reader knows which their report meant.
 *
 * Two rows carrying whitespace is the whole test. It is deliberately
 * weak, because it decides whether to *offer* and never whether to
 * take: a clean IOC list almost never trips it, and a `text` value
 * that does costs the reader a line they can ignore.
 */
$wordy = isset($report['wordy']) ? (int)$report['wordy'] : 0;
$unread = isset($report['unread']) ? (int)$report['unread'] : 0;
$offerExtract = !$extracted && $wordy >= 2;
?>
<div class="vi-work" data-vi-work
     data-vi-assess="<?= h($this->Html->url(array(
         'controller' => 'values',
         'action' => 'assess',
     ))) ?>">
    <div class="ifp-row vi-work__bar">
        <span class="ifp-count"><?= sprintf(h(__n('%s value to review',
            '%s values to review', count($rows))), '<b>' . h(count($rows)) . '</b>') ?></span>
        <span class="vi-prov"><?= h($lead) ?>
<?php if ($did): ?>
            <?= h(ucfirst(implode(', ', $did)) . '.') ?>
<?php else: ?>
            <?= h(__('No changes were needed.')) ?>
<?php endif; ?>
        </span>
        <div class="vi-chrome vi-work__tools">
            <?php
            /*
             * The one sentence that says where the reader is, and the only
             * thing on this page that is announced. Every wording travels
             * with the markup, as the prompt's verb does: a sentence built
             * in a `.js` file is a sentence no catalogue translates.
             */
            ?>
            <span class="vi-progress" data-vi-progress
                  aria-live="polite"
                  data-vi-filling="<?= h(__('%1$d of %2$d assessed,'
                      . ' %3$d reviewed')) ?>"
                  data-vi-worked="<?= h(__('All %d reviewed')) ?>"
                  data-vi-left="<?= h(__('%1$d of %2$d reviewed, %3$d'
                      . ' left')) ?>"
                  data-vi-lost="<?= h(__('%d failed to load')) ?>"></span>
            <div class="ifp-segv vi-flts" role="group" aria-label="<?= h(__('Show')) ?>">
                <button class="ifp-segv-btn vi-flt" type="button" data-vi-f="all"
                        aria-pressed="true"><?= h(__('All')) ?> <b></b></button>
                <button class="ifp-segv-btn vi-flt" type="button" data-vi-f="todo"
                        aria-pressed="false"><?= h(__('To review')) ?> <b></b></button>
                <button class="ifp-segv-btn vi-flt" type="button" data-vi-f="opened"
                        aria-pressed="false"><?= h(__('Opened')) ?> <b></b></button>
                <button class="ifp-segv-btn vi-flt" type="button" data-vi-f="cleared"
                        aria-pressed="false"><?= h(__('Dismissed')) ?> <b></b></button>
            </div>
<?php if ($showsAssessment): ?>
            <button class="ifp-fbtn vi-sort" type="button" data-vi-sort
                    aria-pressed="false">
                <i class="fas fa-arrow-down-wide-short" aria-hidden="true"></i>
                <span><?= h(__('Worst first')) ?></span>
            </button>
<?php endif; ?>
            <div class="ifp-segv" role="group" aria-label="<?= h(__('View')) ?>">
                <button class="ifp-segv-btn" type="button" data-vi-view="table"
                        aria-pressed="true" title="<?= h(__('Table view')) ?>"
                        aria-label="<?= h(__('Table view')) ?>"><i class="fas fa-list" aria-hidden="true"></i></button>
                <button class="ifp-segv-btn" type="button" data-vi-view="cards"
                        aria-pressed="false" title="<?= h(__('Card view')) ?>"
                        aria-label="<?= h(__('Card view')) ?>"><i class="fas fa-th-large" aria-hidden="true"></i></button>
            </div>
        </div>
    </div>
<?php if ($extracted): ?>
<?php
    /*
     * **The line the mode cannot ship without** (§11.3.3, V20). The
     * extractor recognises about half of what a MISP instance holds
     * and says nothing about the rest, so a paste that lost a `mutex`,
     * a `cpe` or a user-agent has to say so here — otherwise the
     * reader cannot tell *nobody recorded it* from *nothing asked*,
     * which is the one confusion this page's rules forbid.
     *
     * A line is counted only when the reader plainly meant it as a
     * value; `ValueInputTool::unreadLines()` has the rule. Naming the
     * first one is what makes the number checkable — a reader who
     * sees their own string knows immediately whether the rest of the
     * count is worth acting on.
     */
?>
<?php   if ($unread > 0): ?>
    <p class="vi-unread">
        <b><?= h(sprintf(__n('%d line looks like a value but could'
            . ' not be extracted.', '%d lines look like values but could'
            . ' not be extracted.', $unread), $unread)) ?></b>
<?php     if ($report['unread_example'] !== null): ?>
        <?php
        /*
         * The em-dash after the example rather than a full stop: the
         * `code` span carries its own padding and a border, so a
         * period set against it reads as a floating dot.
         */
        ?>
        <?= h(__('The first one is')) ?>
        <code class="vi-said-inline"><?= h(
            $report['unread_example']
        ) ?></code> &mdash;
        <?= h(__('extraction only picks up values it can give an'
            . ' attribute type.')) ?>
<?php     else: ?>
        <?= h(__('Extraction only picks up values it can give an'
            . ' attribute type.')) ?>
<?php     endif; ?>
    </p>
<?php   endif; ?>
    <?= $this->element('Values/Index/reread', array(
        'extract' => 0,
        'label' => __('Look up each line instead'),
        'note' => $unread > 0
            ? __('To look up every line exactly as pasted:')
            : __('If each line was meant to be a value:'),
    )) ?>
<?php elseif ($offerExtract): ?>
    <?= $this->element('Values/Index/reread', array(
        'extract' => 1,
        'label' => __('Extract values from the text instead'),
        'note' => sprintf(__n('%d row looks like text rather than a'
            . ' value. If you pasted a report:',
            '%d rows look like text rather than values. If you'
            . ' pasted a report:', $wordy), $wordy),
    )) ?>
<?php endif; ?>
<?php if ($byCommas && count($rows) > 1): ?>
    <?php
    /*
     * The one paste whose reading is genuinely ambiguous, offered
     * rather than decided (§7.2). A value may legitimately contain a
     * comma — a `text` attribute does — and on one line the commas
     * are the only separator there is, so splitting is the reading
     * that serves nearly everybody and the offer serves the rest.
     * Its own form, because `FormHelper` hashes a field list together
     * with the action it posts to, and this one posts to `resolve`
     * from inside a fragment `triage` rendered.
     */
    echo $this->Form->create('Value', array(
        'class' => 'vi-whole',
        'url' => $this->Html->url(array(
            'controller' => 'values',
            'action' => 'resolve',
        )),
    ));
    echo $this->Form->hidden('value', array(
        'value' => isset($this->request->data['Value']['value'])
            ? $this->request->data['Value']['value']
            : '',
    ));
    echo $this->Form->hidden('whole', array('value' => 1));
    ?>
        <span class="vi-mark"><?= h(__(
            'If those commas are part of one value:'
        )) ?></span>
        <button type="submit" class="vi-btn"><?= h(__(
            'Open the whole line as one value'
        )) ?></button>
    <?= $this->Form->end() ?>
<?php endif; ?>
    <?php
    /*
     * The sort note says what the order now means, because a table
     * a reader can no longer check line by line against their own
     * source has stopped being the thing they pasted. Its two
     * wordings differ in one clause — whether anything is still
     * arriving — because a row cannot be ranked before it has an
     * answer, and a reader watching rows jump needs telling that
     * the ones below are not last, only unanswered.
     */
    ?>
    <div class="vi-sortnote" data-vi-sortnote hidden
         data-vi-mid="<?= h(__('Sorted by assessment: %1$d ranked'
             . ' so far. The %2$d still loading stay at the bottom'
             . ' until they are assessed.')) ?>"
         data-vi-settled="<?= h(__('Sorted by assessment.')) ?>"
         data-vi-back="<?= h(__('Back to paste order')) ?>"></div>
    <div class="card shadow-sm vi-work__card">
    <div class="vi-listwrap is-table<?= $showsAssessment ? '' : ' is-unassessed' ?>">
        <div class="vi-thead" aria-hidden="true">
            <span></span>
            <span><?= h(__('Value')) ?></span>
            <span class="vi-c-types"><?= h(__('Types')) ?></span>
            <span class="vi-c-lean"><?= h(__('Lean')) ?></span>
            <span class="vi-c-strength"><?= h(__('Signal strength')) ?></span>
            <span class="vi-c-rel"><?= h(__('Relevance')) ?></span>
            <span class="vi-c-num vi-c-orgs"><?= h(__('Orgs')) ?></span>
            <span class="vi-c-sig"><?= h(__('Sightings')) ?></span>
            <span></span>
        </div>
        <ol class="vi-rows<?= $batched ? '' : ' vi-rows--short' ?>"
            data-vi-rows tabindex="0" role="list"
            aria-label="<?= h(__('Values to review')) ?>">
<?php foreach ($rows as $i => $row): ?>
            <?php
            /*
             * **The assessment is asked about the instance's spelling
             * and the row shows the reader's.** Sent the reader's, the
             * row would carry a verdict on a string nobody filed, and
             * would then disagree with the profile the same row links
             * to. Where the instance holds no spelling there is
             * nothing to prefer, and the reader's own is what a value
             * nobody recorded is asked about.
             */
            $asked = $row['stored'] === null
                ? $row['value']
                : $row['stored'];
            ?>
            <li class="vi-row" data-vi-row="<?= h($i) ?>"
                data-vi-value="<?= h($asked) ?>">
                <?php
                /*
                 * The gutter carries the row's ordinal until the
                 * script takes it over for the state mark. Without a
                 * script there is no state to draw and the number is
                 * the more useful thing — it is also the list phase 4
                 * shipped, unchanged.
                 */
                ?>
                <span class="vi-rail" data-vi-rail><?= h($i + 1) ?></span>
                <span class="vi-fill" data-vi-fill>
                    <div class="vi-card">
                        <div class="vi-l1">
                            <span class="vi-val"><?= h($row['value']) ?></span>
                        </div>
                        <div class="vi-pend" aria-hidden="true">
                            <i class="vi-bar" style="width:86px"></i>
                            <i class="vi-bar" style="width:44px"></i>
                            <i class="vi-bar" style="width:120px"></i>
                            <span class="vi-pendtxt vi-pendtxt--queued"><?= h(__(
                                'queued')) ?></span>
                            <span class="vi-pendtxt vi-pendtxt--flight"><?= h(__(
                                'assessing…')) ?></span>
                        </div>
                        <div class="vi-fail"><?= h(__('The assessment'
                            . ' failed to load, so this value\'s status is'
                            . ' unknown.')) ?></div>
                    </div>
                    <div class="vi-cells">
                        <div class="vi-c-val">
                            <div class="attr-value">
                                <div class="attr-value-line">
                                    <p class="fw-semibold mb-0 vi-c-valtext"><?= h($row['value']) ?></p>
                                </div>
                            </div>
                        </div>
                        <span class="vi-c-types"></span>
                        <span class="vi-c-lean"><i class="vi-bar" style="width:72px"></i></span>
                        <span class="vi-c-strength"></span>
                        <?php
                        /*
                         * One cell holding both wordings, never two
                         * cells: a hidden grid item leaves its column
                         * to the next one along, and a row whose
                         * columns slide by one is the alignment this
                         * view exists for, gone.
                         */
                        ?>
                        <span class="vi-c-rel"><span
                            class="vi-pendtxt vi-pendtxt--queued"><?= h(__(
                            'queued')) ?></span><span
                            class="vi-pendtxt vi-pendtxt--flight"><?= h(__(
                            'assessing…')) ?></span></span>
                        <span class="vi-c-num vi-c-orgs"></span>
                        <span class="vi-c-sig"></span>
                        <span class="vi-c-say"><?= h(__('The assessment'
                            . ' failed to load.')) ?></span>
                    </div>
                    <div class="vi-acts">
                        <button type="button" class="vi-btn vi-retry"
                                data-vi-act="retry"><?= h(__(
                            'Retry')) ?></button>
                        <a class="vi-btn" target="_blank" rel="noopener"
                           href="<?= h($this->Html->url(array(
                               'controller' => 'values',
                               'action' => 'view',
                               ValueUrlTool::address($asked),
                           ))) ?>"><?= h(__('Open')) ?><span
                           class="vi-cardonly"> <?= h(__('intelligence')) ?></span></a>
                    </div>
                </span>
            </li>
<?php endforeach; ?>
        </ol>
        <?php
        /*
         * A filter that subtracts every row is a working filter, not a
         * broken list, and an empty box with no explanation is
         * indistinguishable from one that failed to load.
         */
        ?>
        <p class="vi-empty" data-vi-empty hidden><?= h(__('Nothing'
            . ' matches this filter. Switch back to All.')) ?></p>
    </div>
    </div>
    <?php
    /*
     * The end of the batch, and the one thing a page that writes
     * nothing can still hand over: the shortlist. It is rendered with
     * the rows and shown when the last decision is made, so its numbers
     * are filled by the script rather than built by it.
     */
    ?>
    <section class="card shadow-sm vi-done" data-vi-done hidden
             aria-labelledby="vi-done-title">
        <div class="vi-done__main">
            <span class="vi-done__ico" aria-hidden="true"><i class="fas fa-circle-check"></i></span>
            <div class="vi-done__text">
                <h3 class="vi-done__title" id="vi-done-title" data-vi-done-lead
                    data-vi-tpl="<?= h(__('All %d values reviewed')) ?>"></h3>
                <p class="vi-done__tally">
                    <span class="vi-done__n is-opened">
                        <i class="fas fa-arrow-up-right-from-square" aria-hidden="true"></i>
                        <span data-vi-done-opened
                              data-vi-tpl="<?= h(__('%d opened')) ?>"></span>
                    </span>
                    <span class="vi-done__n">
                        <i class="fas fa-xmark" aria-hidden="true"></i>
                        <span data-vi-done-cleared
                              data-vi-tpl="<?= h(__('%d dismissed')) ?>"></span>
                    </span>
                </p>
            </div>
            <div class="vi-done__acts">
                <button type="button" class="btn btn-primary btn-sm vi-done__copy"
                        data-vi-copy
                        data-vi-tpl-one="<?= h(__('Copy the opened value')) ?>"
                        data-vi-tpl="<?= h(__('Copy the %d opened values')) ?>"
                        data-vi-copied="<?= h(__('Copied')) ?>">
                    <i class="fas fa-copy" aria-hidden="true"></i>
                    <span data-vi-copy-label></span>
                </button>
                <button type="button" class="btn btn-outline-secondary btn-sm" data-vi-again>
                    <i class="fas fa-rotate-left" aria-hidden="true"></i>
                    <?= h(__('Start over')) ?>
                </button>
            </div>
        </div>
        <p class="vi-done__note">
            <i class="fas fa-circle-info" aria-hidden="true"></i>
            <?= h(__('This progress is not saved and is lost when you close'
                . ' the tab. Paste a new list above to start another.')) ?>
        </p>
        <textarea class="vi-shortlist" data-vi-short hidden readonly rows="3"
                  aria-label="<?= h(__('The values you opened')) ?>"></textarea>
    </section>
    <?php
    /*
     * Nothing on this page writes (§0), so the progress lives in one
     * browser tab — and a reader who worked forty rows and then lost
     * them to a refresh was not told.
     */
    ?>
    <p class="vi-chrome vi-work__foot">
        <span class="vi-keys">
            <span><kbd>j</kbd><kbd>k</kbd> <?= h(__('move')) ?></span>
            <span><kbd>o</kbd> <?= h(__('open')) ?></span>
            <span><kbd>x</kbd> <?= h(__('dismiss')) ?></span>
            <span><kbd>u</kbd> <?= h(__('undo')) ?></span>
        </span>
        <span><?= h(__('Progress is kept in'
            . ' this tab only; nothing is saved to MISP.')) ?></span>
    </p>
</div>
