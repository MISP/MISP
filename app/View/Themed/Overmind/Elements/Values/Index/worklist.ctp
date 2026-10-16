<?php
/**
 * A pasted list, as the rows to work.
 *
 * `02b-proposal-c.html`'s worklist. Phase 4 built the rows and what the
 * parse did to get to them; phase 5 gives them their assessments and,
 * with them, the machine C is for — the progress tape, a mark per row,
 * the *left to do* filters, the worst-first sort, the compact table
 * view and the line saying where the marks live.
 *
 * **That chrome arrives with its subject and not before.** Until there
 * were decisions to work, a tape would have been one colour, a filter
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
    <p class="vi-prov">
        <b><?= h($lead) ?></b>
<?php if ($did): ?>
        <?= h(ucfirst(implode(', ', $did)) . '.') ?>
<?php else: ?>
        <?= h(__('No changes were needed.')) ?>
<?php endif; ?>
        <?= h(__('Your original paste is still in the box above.')) ?>
    </p>
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
    <div class="vi-chrome">
        <div class="vi-tapewrap">
            <?php
            /*
             * The one sentence that says where the reader is. It moves
             * twice — once as the assessments land, once as decisions
             * are made — and it is the only thing on this page that is
             * announced, because a batch's progress is exactly what a
             * reader who has looked away needs told.
             */
            ?>
            <?php
            /*
             * Every wording travels with the markup, as the prompt's
             * verb does: a sentence built in a `.js` file is a
             * sentence no catalogue translates.
             */
            ?>
            <span class="vi-progress" data-vi-progress
                  aria-live="polite"
                  data-vi-filling="<?= h(__('%1$d of %2$d assessed,'
                      . ' %3$d reviewed')) ?>"
                  data-vi-worked="<?= h(__('All %d reviewed')) ?>"
                  data-vi-left="<?= h(__('%1$d of %2$d reviewed, %3$d'
                      . ' left')) ?>"
                  data-vi-lost="<?= h(__('%d failed to load')) ?>"
                  ></span>
<?php if ($batched): ?>
            <span class="vi-tape" data-vi-tape role="group"
                  aria-label="<?= h(__('Batch progress')) ?>"></span>
<?php endif; ?>
        </div>
<?php if ($batched): ?>
        <div class="vi-legend">
            <span><span class="vi-swatch" data-s="queued"></span><?= h(__(
                'queued')) ?></span>
            <span><span class="vi-swatch" data-s="flight"></span><?= h(__(
                'being assessed')) ?></span>
            <span><span class="vi-swatch" data-s="todo"></span><?= h(__(
                'assessed, not yet reviewed')) ?></span>
            <span><span class="vi-swatch" data-s="opened"></span><?= h(__(
                'opened')) ?></span>
            <span><span class="vi-swatch" data-s="cleared"></span><?= h(__(
                'dismissed')) ?></span>
        </div>
<?php endif; ?>
        <div class="vi-controls">
            <span class="vi-segs" data-vi-filters>
                <button class="vi-seg" type="button" data-vi-f="all"
                        aria-pressed="true"><?= h(__('All')) ?> <b></b></button>
                <button class="vi-seg" type="button" data-vi-f="todo"
                        aria-pressed="false"><?= h(__('To review')) ?> <b></b></button>
                <button class="vi-seg" type="button" data-vi-f="opened"
                        aria-pressed="false"><?= h(__('Opened')) ?> <b></b></button>
                <button class="vi-seg" type="button" data-vi-f="cleared"
                        aria-pressed="false"><?= h(__('Dismissed')) ?> <b></b></button>
            </span>
            <span class="vi-segs">
                <button class="vi-seg" type="button" data-vi-sort
                        aria-pressed="false"><?= h(__('Worst first')) ?></button>
            </span>
            <span class="vi-segs" data-vi-views>
                <button class="vi-seg" type="button" data-vi-view="cards"
                        aria-pressed="true"><?= h(__('Cards')) ?></button>
                <button class="vi-seg" type="button" data-vi-view="table"
                        aria-pressed="false"><?= h(__('Table')) ?></button>
            </span>
            <span class="vi-keys">
                <span><span class="vi-kbd">j</span> <span class="vi-kbd">k</span> <?= h(__('move')) ?></span>
                <span><span class="vi-kbd">o</span> <?= h(__('open')) ?></span>
                <span><span class="vi-kbd">x</span> <?= h(__('dismiss')) ?></span>
                <span><span class="vi-kbd">u</span> <?= h(__('undo')) ?></span>
                <?php
                /*
                 * Printed beside the controls it qualifies rather than
                 * in a footnote. Nothing on this page writes (§0), so
                 * a progress model built on it lives in one browser
                 * tab — and a reader who worked forty rows and then
                 * lost them to a refresh was not told.
                 */
                ?>
                <span class="vi-tabonly"><?= h(__('Progress is kept in'
                    . ' this tab only; nothing is saved to MISP.')) ?></span>
            </span>
        </div>
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
    </div>
    <div class="vi-listwrap">
        <div class="vi-thead" aria-hidden="true">
            <span></span>
            <span><?= h(__('value')) ?></span>
            <span class="vi-c-types"><?= h(__('types')) ?></span>
            <span class="vi-c-lean"><?= h(__('lean')) ?></span>
            <span class="vi-c-strength"><?= h(__('signal strength')) ?></span>
            <span class="vi-c-rel"><?= h(__('relevance')) ?></span>
            <span class="vi-c-num vi-c-orgs"><?= h(__('orgs')) ?></span>
            <span class="vi-c-num vi-c-sig"><?= h(__('sightings')) ?></span>
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
                        <span class="vi-c-val">
                            <span class="vi-c-valtext"><?= h($row['value']) ?></span>
                        </span>
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
                        <span class="vi-c-num vi-c-sig"></span>
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
                               ValueUrlTool::encode($asked),
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
    <?php
    /*
     * The end of the batch, and the one thing a page that writes
     * nothing can still hand over: the shortlist. It is rendered with
     * the rows and shown when the last decision is made, so the two
     * numbers in it are filled by the script rather than built by it.
     */
    ?>
    <div class="vi-done" data-vi-done hidden>
        <h3 data-vi-done-lead
            data-vi-tpl="<?= h(__('All %d values reviewed.')) ?>"></h3>
        <p><span data-vi-done-counts
                 data-vi-tpl="<?= h(__('%1$d opened, %2$d dismissed.')) ?>"></span>
            <?= h(__('This progress is not saved and is lost when you'
                . ' close the tab. Copy the values you opened to keep'
                . ' them.')) ?></p>
        <div class="vi-offer">
            <button type="button" class="vi-btn vi-btn--lead"
                    data-vi-copy
                    data-vi-tpl="<?= h(__('Copy the %d opened values')) ?>"></button>
            <button type="button" class="vi-btn" data-vi-again><?= h(__(
                'Start over')) ?></button>
            <span class="vi-mark"><?= h(__('Or paste a new list'
                . ' above.')) ?></span>
        </div>
        <textarea class="vi-shortlist" data-vi-short hidden
                  aria-label="<?= h(__('The values you opened')) ?>"></textarea>
    </div>
</div>
