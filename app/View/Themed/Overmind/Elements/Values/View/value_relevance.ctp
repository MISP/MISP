<?php
/**
 * How fresh this value is, and what made it so — as a rail card.
 *
 * The decay card's replacement (`prd/analyst-profile/06-staleness.md`
 * §4). That card showed one bar per decaying model, each a score MISP
 * computes largely from the value's tags multiplied by a time factor —
 * the same tags the assessment's signal-strength ledger scores directly, with a
 * per-row audit trail and none of the double counting. This card keeps
 * the time factor and drops the base score, so what is on screen is one
 * quantity a reader can act on: **how much shelf life is left, measured
 * from the last time somebody new confirmed the value.**
 *
 * Everything the number is made of is on the card, because a TTL with
 * no provenance is how a reader concludes the page is wrong about a
 * value they know well (§3.4): the clock's date and who supplied it,
 * the type that supplied the TTL and whether the value's other types
 * would have given a different one, and the rule in force. The
 * corroboration timeline underneath is the aggregation rule's second
 * half — naming what holds the number, which is what phase 23 decided
 * for the decay maximum and this inherits (§4.1).
 *
 * Three honest states it must never render as a blank or a zero:
 *
 *   - **nothing has ever corroborated it.** The majority case in
 *     production — one organisation, no sightings — where the clock
 *     falls back to the value's own encoding date and says so.
 *   - **the timeline is not trustworthy.** No `first_seen`, or an
 *     encoding date that lags the event's own dates, so the elapsed
 *     time is measured from something that is not an observation
 *     (§3.6).
 *   - **the sighting half could not be read**, because MISP flagged the
 *     value as over-correlating and the budget left its rows unfetched.
 *
 * **Every fact above is required; none of them was required to be a
 * paragraph.** The card shipped with fourteen lines of explanation
 * around ten lines of data — a TTL line that printed the engine's whole
 * resolution (`shortest rule, over ip-src 90, text 180`), two sentences
 * on what the neighbouring chart does, one on what does *not* move it,
 * and `lower bound`, `encoding date` and `first_seen` where plain words
 * exist. This pass keeps the facts and moves the second half of each to
 * its element's `title`: the per-type day counts, the clock setting's
 * name, the false-positive rule, what an over-correlating value is.
 * Hovers, not sentences, so §3.4's honest state survives at a third of
 * the height. The labels this card invented — `new organisation`,
 * `independent sighting` — carry their definition the same way, which
 * they never did in any form.
 *
 * Lazily loaded from ValuesController::viewRelevance.
 *
 * @var array $valueIntelligence
 * @var string $valueB64
 */
App::uses('ValueRelevanceTool', 'Tools/ValueIntelligence');
$relevance = $valueIntelligence['relevance'];
$sightings = $valueIntelligence['sightings'];
$notes = $valueIntelligence['sighting_notes'];

/*
 * The labels this card invented — `new organisation`, `independent
 * sighting` — and the sentence behind each are `ValueRelevanceTool`'s
 * now, beside `clockLabel()` and for its reason: they are read on three
 * surfaces since the Assessment tab drew the axis too, and the copy
 * that does not get updated is the one that prints `org_joined` at a
 * reader.
 */
$state = $relevance['state'];
$clock = $relevance['clock'];
$ttl = $relevance['ttl'];
?>
<div class="card shadow-sm mb-3 vp-panel vp-aside"
     style="--vp-panel-color: var(--correlation);">

    <div class="vp-aside-head">
        <i class="fas fa-hourglass-half"
           title="<?= h(__('How long this value counts as current after'
               . ' the last time somebody confirmed it.')) ?>"
           style="color: var(--correlation);"></i>
        <span class="vp-aside-title"><?= __('Lifetime') ?></span>
        <?php if ($state !== null): ?>
            <?php
            /*
             * `TTL 90 days` twice over: an acronym a reader has to
             * expand, in front of a number the card then spends three
             * lines accounting for. The whole length, said plainly, is
             * what the days-left figure beside it is measured against.
             */
            ?>
            <span class="vp-aside-meta"
                  title="<?= h(__('The full lifetime. The days left'
                      . ' below are what is unused of it.')) ?>">
                <?= h(sprintf(
                    __('%s days in total'),
                    $ttl['days']
                )) ?>
            </span>
        <?php endif; ?>
    </div>

    <div class="p-3 d-flex flex-column gap-3">

        <?php
        /*
         * The axis itself, in the element the Assessment tab's clock
         * band draws from the same block. The no-clock state travels
         * inside it rather than being each caller's to remember: a
         * surface that forgets prints `expired` for a value that has no
         * date at all.
         */
        ?>
        <?= $this->element('Values/View/value_relevance_facts', array(
            'relevance' => $relevance,
        )) ?>

        <?php if ($state !== null): ?>

            <?php
            /*
             * The dates the axis is built on, side by side. Shared with
             * the profile editor's bench, which shows the same value
             * under the knobs that produce these numbers — one element
             * so the two panes cannot drift into describing the same
             * columns differently.
             */
            ?>
            <?php if (!empty($valueIntelligence['timeline_facts'])): ?>
                <?= $this->element('Values/View/value_date_sources', array(
                    'facts' => $valueIntelligence['timeline_facts'],
                    'clockKind' => $clock['kind'],
                    'clockLabel' => ValueRelevanceTool::clockLabel(
                        $clock['setting']
                    ),
                    'lastSighting' => $sightings['last_stamp'] ?? null,
                    'sightingTotal' => (int)($sightings['total'] ?? 0),
                )) ?>
            <?php endif; ?>

            <?php if (!empty($clock['events'])): ?>
                <?= $this->element(
                    'Values/View/value_relevance_events',
                    array('clock' => $clock)
                ) ?>
            <?php endif; ?>

            <?php
            /*
             * Four lines pointing at a chart in the next column, two of
             * them spent on what *does not* move it. Kept, because the
             * chart and this card are the same quantity drawn twice and
             * a reader who misses that reads them as disagreeing — but
             * at the length of a caption, with the false-positive rule
             * on the hover rather than in its own sentence.
             */
            ?>
            <p class="vp-aside-note"
               title="<?= h(__('A false positive is drawn on that chart'
                   . ' too. A report arguing against a value never'
                   . ' extends its lifetime.')) ?>">
                <?= h(__(
                    'The chart plots this bar over time: it steps back'
                    . ' up on each of the dates listed here, and never'
                    . ' on a false positive.'
                )) ?>
            </p>

            <?php if (!empty($relevance['sightings_excluded'])): ?>
                <p class="vp-aside-note"
                   title="<?= h(__('The profile excludes sightings an'
                       . ' organisation files on its own report.')) ?>">
                    <?= h(sprintf(
                        __n(
                            'One self-sighting does not count as a'
                                . ' confirmation here.',
                            '%s self-sightings do not count as'
                                . ' confirmations here.',
                            $relevance['sightings_excluded']
                        ),
                        $relevance['sightings_excluded']
                    )) ?>
                </p>
            <?php endif; ?>

            <?php
            /*
             * The instance's sighting policy, which is what
             * `05-exclusions.md` §7.2 leaves standing when it removes
             * every per-value statement about a reader's permissions:
             * this says what the *instance* is configured to do, on
             * every value, and reveals nothing about the one on screen.
             */
            ?>
            <div class="vp-acl-note vp-acl-note-band">
                <i class="fas fa-user-shield"
                   title="<?= h(__('What your account is allowed to'
                       . ' see')) ?>"></i>
                <span><?= h($notes['policy']) ?></span>
            </div>

            <?php if ($relevance['profile'] !== null): ?>
                <p class="vp-aside-note"
                   title="<?= h(__('The clock, the curve and the day'
                       . ' counts per type are all profile'
                       . ' settings.')) ?>">
                    <?= h(sprintf(
                        __('Every number here is a setting of the %s'
                            . ' profile, which an analyst can edit.'),
                        $relevance['profile']
                    )) ?>
                </p>
            <?php endif; ?>

        <?php endif; ?>

    </div>

</div>
