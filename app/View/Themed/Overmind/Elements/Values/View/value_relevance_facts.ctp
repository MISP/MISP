<?php
/**
 * The relevance axis, and everything the number is made of.
 *
 * Extracted from `value_relevance.ctp` so the Assessment tab can draw
 * the axis it was only summarising. Until 2026-09-13 relevance reached
 * that tab as one clause of the hero's sentence and a bare chart in the
 * rail, while lean carried its rule and its per-organisation table and
 * signal strength carried the whole ledger — two axes showing their work and
 * the third asserting a number. Nothing about the data made that
 * necessary: `$verdict['relevance']` is the same block this element
 * reads, already built by the same `ValueRelevanceTool::relevanceFor()`
 * call, so the tab was holding every fact below and printing one of
 * them.
 *
 * **One element rather than a second rendering**, and that is the point
 * of extracting it rather than writing it. Two panels computing one
 * quantity twice is the defect this corpus has now shipped three times
 * — phase 5's bar against its series, §14.3's *expired* beside
 * *64 days left*, §16's opinion mean — and the axis with no shared
 * element was the axis that broke. The facts are a pure function of the
 * block, so a surface that draws them cannot drift from a surface that
 * draws them; only the chrome around it differs.
 *
 * Everything the number is made of is here, because a TTL with no
 * provenance is how a reader concludes the page is wrong about a value
 * they know well (`06-staleness.md` §3.4): the clock's date and who
 * supplied it, the type that supplied the TTL and whether the value's
 * other types would have given a different one, and the rule in force.
 *
 * Three honest states it must never render as a blank or a zero:
 *
 *   - **nothing has ever corroborated it.** The majority case in
 *     production — one organisation, no sightings — where the clock
 *     falls back to the value's own encoding date and says so.
 *   - **the timeline is not trustworthy.** No `first_seen`, or an
 *     encoding date that lags the event's own dates, so the elapsed
 *     time is measured from something that is not an observation.
 *   - **the sighting half could not be read**, because MISP flagged the
 *     value as over-correlating and the budget left its rows unfetched.
 *
 * The no-clock state is here too, rather than in each caller: a value
 * this reader holds no occurrence of has no date to measure from, and
 * printing `expired` would be inventing an assertion in order to age
 * it.
 *
 * @var array $relevance The `relevance` block, from either
 *                       `ValueIntelligence::forRelevance()` or the
 *                       assessment's own `$verdict['relevance']`
 */
App::uses('ValueRelevanceTool', 'Tools/ValueIntelligence');

$state = $relevance['state'];
?>
<?php if ($state === null): ?>
    <?php
    /*
     * **Two silences, and they are not the same silence.**
     * `noClock()` has returned a `reason` since phase 5 and says in its
     * own docblock that a caller should branch on it; no caller did,
     * so a value MISP flags as over-correlating — one with hundreds of
     * occurrences — was told *nothing is recorded for this value*. It
     * is the sentence that would make a reader who knows the value
     * conclude the page is broken, and it was only ever wrong on the
     * values most likely to be looked at.
     *
     * `rows_not_read` is §14.3's stand-down in words: the clock is
     * missing its sighting half, a half-read clock can only run slow,
     * and an axis that cannot measure says so rather than guessing low.
     */
    ?>
    <div class="vp-empty vp-empty-inline">
        <i class="fas fa-hourglass-half"></i>
        <?php if (($relevance['reason'] ?? null) === 'rows_not_read'): ?>
            <span title="<?= h(__('MISP stops correlating a value that'
                     . ' appears in too many events.')) ?>">
                <?= __('This value is too common for MISP to correlate,'
                    . ' so its reports were not read and no shelf life'
                    . ' is shown.') ?>
            </span>
        <?php else: ?>
            <span><?= __('Nothing is recorded for this value, so there'
                . ' is no clock to run.') ?></span>
        <?php endif; ?>
    </div>
<?php else: ?>
    <?php
    $clock = $relevance['clock'];
    $ttl = $relevance['ttl'];
    $stateHint = ValueRelevanceTool::stateHint($state);
    ?>
    <div class="vp-shelf vp-shelf-<?= h($state) ?>">

        <div class="vp-shelf-head">
            <span class="vp-shelf-state"<?= $stateHint === null
                ? ''
                : ' title="' . h($stateHint) . '"' ?>>
                <?= h(ValueRelevanceTool::stateLabel($state)) ?>
            </span>
            <span class="vp-shelf-days">
                <?php if ($relevance['runway_days'] > 0): ?>
                    <?= h(sprintf(
                        __n(
                            '%s day left',
                            '%s days left',
                            $relevance['runway_days']
                        ),
                        $relevance['runway_days']
                    )) ?>
                <?php elseif ($relevance['runway_days'] === 0): ?>
                    <?= __('expires today') ?>
                <?php else: ?>
                    <?= h(sprintf(
                        __n(
                            '%s day over',
                            '%s days over',
                            -$relevance['runway_days']
                        ),
                        -$relevance['runway_days']
                    )) ?>
                <?php endif; ?>
            </span>
        </div>

        <?php
        /*
         * The assumed days are drawn, not just stated. A track whose
         * fill silently included 30 days nobody measured is the failure
         * this replaced in a new costume — so the assumed stretch is
         * its own hatched segment, between what the rows support and
         * what is left.
         */
        $assumed = (int)($relevance['assumed_days'] ?? 0);
        /*
         * In the track's own coordinates, which are runway remaining
         * and not elapsed days: the assumption ate the stretch between
         * the runway as drawn and the runway the record alone supports,
         * so it sits immediately right of the fill and ends where the
         * bar would have ended without it.
         */
        $runwayPct = (int)round($relevance['runway'] * 100);
        $recordedPct = (int)round(
            ($relevance['recorded_runway'] ?? $relevance['runway'])
            * 100
        );
        $assumedPct = max(0, $recordedPct - $runwayPct);
        ?>
        <div class="vp-shelf-track"
             title="<?= h($assumed > 0
                 ? sprintf(
                     __('%1$s of %2$s days used: %3$s on the record,'
                         . ' %4$s assumed'),
                     $relevance['elapsed_days'],
                     $ttl['days'],
                     $relevance['recorded_days'],
                     $assumed
                 )
                 : sprintf(
                     __('%1$s of %2$s days used'),
                     $relevance['elapsed_days'],
                     $ttl['days']
                 )) ?>">
            <span class="vp-shelf-fill"
                  style="width: <?=
                      (int)round($relevance['runway'] * 100) ?>%;"></span>
            <?php if ($assumed > 0): ?>
                <span class="vp-shelf-assumed"
                      title="<?= h(sprintf(
                          __n(
                              '%s day the profile assumes, because'
                                  . ' nothing records when this was'
                                  . ' seen',
                              '%s days the profile assumes, because'
                                  . ' nothing records when this was'
                                  . ' seen',
                              $assumed
                          ),
                          $assumed
                      )) ?>"
                      style="left: <?= $runwayPct ?>%; width: <?=
                          $assumedPct ?>%;"></span>
            <?php endif; ?>
            <span class="vp-shelf-mark"
                  title="<?= h(__('where it stops counting as current')) ?>"
                  style="left: <?=
                      (int)round(
                          $relevance['aging_fraction'] * 100
                      ) ?>%;"></span>
        </div>

        <?php if (!empty($relevance['uncertain'])): ?>
            <?php
            /*
             * **The assumption, in the words of an assumption.** This
             * block used to print a measured lag — MISP's `Event.date`
             * against a row-modification timestamp — which was not a
             * measurement of anything. What it says now is what the
             * profile is doing and by how much, because a number the
             * reader cannot see is a number they cannot argue with, and
             * this one moves the days-left figure directly above it.
             *
             * `uncertain_note` is not repeated here. With one reason
             * left it says the same sentence back. The note still
             * serves the two panels that have room for nothing longer.
             */
            ?>
            <div class="vp-shelf-why">
                <?= h(__('No occurrence says when this value was seen,'
                    . ' only when it was last edited.')) ?>
                <?php if ($assumed > 0): ?>
                    <?= h(sprintf(
                        __n(
                            'So the %1$s profile reads it as %2$s day'
                                . ' older than its %3$s days on the'
                                . ' record — the hatched part of the'
                                . ' bar.',
                            'So the %1$s profile reads it as %2$s days'
                                . ' older than its %3$s days on the'
                                . ' record — the hatched part of the'
                                . ' bar.',
                            $assumed
                        ),
                        $relevance['profile'] ?? __('active'),
                        $assumed,
                        $relevance['recorded_days']
                    )) ?>
                    <?= h(__('This is an assumption: it makes the value'
                        . ' count as old sooner, but never changes when'
                        . ' its lifetime ends.')) ?>
                <?php else: ?>
                    <?= h(__('It may be older than shown.')) ?>
                <?php endif; ?>
                <?php if (!empty($relevance['assumed_capped'])): ?>
                    <?= h(sprintf(
                        __('The profile would have assumed %s days; the'
                            . ' rest is not applied, because an'
                            . ' assumption may never expire a value on'
                            . ' its own.'),
                        $relevance['assumed_setting']
                    )) ?>
                <?php endif; ?>
            </div>
        <?php endif; ?>

        <?php if (!empty($clock['fallback'])): ?>
            <div class="vp-shelf-why"
                 title="<?= h(__('One organisation reporting a value is'
                     . ' the claim, not its confirmation.')) ?>">
                <?= h(__('Nobody else has confirmed this value, so the'
                    . ' clock runs from the day it was last added'
                    . ' instead.')) ?>
            </div>
        <?php endif; ?>

        <?php
        /*
         * `clock: last independent corroboration` said the setting's
         * name and nothing about what it does, next to a kind it
         * usually repeats word for word. It is the line's hover now — a
         * reader who wants to know which profile knob produced this
         * date can still find it, and one who does not is left with a
         * plain sentence.
         */
        $clockTitle = sprintf(
            __('This profile resets the clock on the %s.'),
            ValueRelevanceTool::clockLabel($clock['setting'])
        );
        ?>
        <div class="vp-shelf-prov" title="<?= h($clockTitle) ?>">
            <?php if (!empty($clock['fallback'])): ?>
                <?= h(sprintf(
                    __('Added %1$s by %2$s'),
                    date('Y-m-d', $clock['at']),
                    $clock['by'] === null
                        ? __('an unnamed organisation')
                        : $clock['by']
                )) ?>
            <?php else: ?>
                <?= h(sprintf(
                    __('Last confirmed %1$s by %2$s (%3$s)'),
                    date('Y-m-d', $clock['at']),
                    $clock['by'] === null
                        ? __('an unnamed organisation')
                        : $clock['by'],
                    ValueRelevanceTool::kindLabel($clock['kind'])
                )) ?>
            <?php endif; ?>
        </div>

        <?php
        /*
         * This line read `TTL 90 days from ip-dst, short bucket ·
         * shortest rule, over ip-src 90, text 180` — the whole
         * resolution, in the order the engine computed it. The facts
         * §3.4 requires are *which type supplied the number* and *that
         * the others disagreed*; the per-type list proving it is the
         * hover, because a reader who has to parse four `type days`
         * pairs to learn `they disagree` has been handed the engine's
         * working rather than its answer.
         */
        $bucketNames = array(
            'short' => __('short'),
            'medium' => __('medium'),
            'long' => __('long'),
            'very_long' => __('very long'),
        );
        $ruleWords = array(
            'shortest' => __('the shortest'),
            'longest' => __('the longest'),
            'most_common' => __('the most common'),
        );
        $ttlTitle = null;
        if ($ttl['type'] === null) {
            $ttlLine = __('No type to take a lifetime from, so the'
                . ' profile default applies.');
        } else {
            if (($ttl['from'] ?? null) === 'bucket'
                && isset($bucketNames[$ttl['bucket']])
            ) {
                $ttlLine = sprintf(
                    __('Lifetime of %1$s (%2$s)'),
                    $ttl['type'],
                    $bucketNames[$ttl['bucket']]
                );
            } elseif (($ttl['from'] ?? null) === 'override') {
                $ttlLine = sprintf(
                    __('Lifetime of %s, set by its own override'),
                    $ttl['type']
                );
            } else {
                $ttlLine = sprintf(
                    __('No lifetime set for %s, so the profile'
                        . ' default applies'),
                    $ttl['type']
                );
            }
            if (!empty($ttl['spread'])) {
                $days = array_column($ttl['candidates'], 'days');
                $ttlLine .= sprintf(
                    __(' — %1$s of its %2$s types (%3$s to %4$s'
                        . ' days).'),
                    $ruleWords[$ttl['rule']] ?? $ttl['rule'],
                    count($ttl['candidates']),
                    min($days),
                    max($days)
                );
                $each = array();
                foreach ($ttl['candidates'] as $candidate) {
                    $each[] = sprintf(
                        __('%1$s: %2$s days'),
                        $candidate['type'],
                        $candidate['days']
                    );
                }
                $ttlTitle = implode(__(' · '), $each);
            } else {
                $ttlLine .= __('.');
            }
        }
        ?>
        <div class="vp-shelf-prov"<?= $ttlTitle === null
            ? ''
            : ' title="' . h($ttlTitle) . '"' ?>>
            <?= h($ttlLine) ?>
        </div>

        <div class="vp-shelf-prov">
            <?php if (!empty($relevance['expired_by'])): ?>
                <?= h(sprintf(
                    __('Filed as expired by %1$s on %2$s'),
                    $relevance['expired_by']['name'],
                    date('Y-m-d', (int)$relevance['expired_by']['at'])
                )) ?>
            <?php else: ?>
                <?= h(sprintf(
                    __('Expires %s'),
                    date('Y-m-d', $relevance['expires_at'])
                )) ?>
            <?php endif; ?>
        </div>

        <?php if (empty($clock['rows_read'])): ?>
            <div class="vp-shelf-why"
                 title="<?= h(__('MISP stops correlating a value that'
                     . ' appears in too many events.')) ?>">
                <?= h(__('This value is too common for MISP to'
                    . ' correlate, so its reports were not read. A'
                    . ' sighting could be newer than the date shown.'))
                    ?>
            </div>
        <?php endif; ?>

    </div>
<?php endif; ?>
