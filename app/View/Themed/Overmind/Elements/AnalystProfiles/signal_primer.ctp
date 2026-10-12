<?php
/**
 * The Signals pane's primer: how the table becomes an assessment.
 *
 * @var array $primer AnalystProfileFormTool::signalPrimer()
 */
$bands = array(
    'none' => __('None'),
    'low' => __('Low'),
    'medium' => __('Medium'),
    'high' => __('High'),
);
$clamp = $primer['clamp'];
?>
<div class="sig-pop-body" aria-labelledby="sig-pop-title-primer">
    <div class="sig-pop-head">
        <div class="sig-pop-titles">
            <p class="sig-pop-title" id="sig-pop-title-primer"><?=
                h(__('How signals add up')) ?></p>
            <p class="sig-pop-sub"><?= h(__('Read this once; each'
                . ' signal\'s own "How it works" says the rest.')) ?></p>
        </div>
        <button type="button" class="sig-pop-close" data-ap-help-close
                aria-label="<?= h(__('Close')) ?>">
            <i class="fa-solid fa-xmark" aria-hidden="true"></i>
        </button>
    </div>
    <div class="sig-pop-grid">
        <div class="sig-pop-col" data-col="a">
            <h4><?= h(__('Every row is one kind of evidence')) ?></h4>
            <p><?= h(__('Each signal looks at one thing MISP knows about the'
                . ' value (who reported it, who sighted it, what it was'
                . ' attributed to) and turns it into points. A plus means'
                . ' the record carries something; a minus means it lacks'
                . ' it.')) ?></p>
            <h4><?= h(__('The points make the signal strength')) ?></h4>
            <p><?= h(__('Signal strength says how well documented the'
                . ' record is, not whether the value is bad. The points of'
                . ' every ticked signal add up into one number, which falls'
                . ' in a band:')) ?></p>
            <ol class="sig-pop-bands">
                <li><span class="pill t-plain"><?= h($bands['low']) ?></span>
                    <span><?= h(sprintf(__('under %s points'),
                        $primer['medium'])) ?></span></li>
                <li><span class="pill t-plain"><?= h($bands['medium']) ?></span>
                    <span><?= h(sprintf(__('from %s points'),
                        $primer['medium'])) ?></span></li>
                <li><span class="pill t-plain"><?= h($bands['high']) ?></span>
                    <span><?= h(sprintf(__('from %1$s points, with at least'
                        . ' %2$s signals adding some'), $primer['high'],
                        $primer['min_signals'])) ?></span></li>
            </ol>
            <?php if ($clamp !== null): ?>
                <p class="sig-pop-note">
                    <i class="fa-solid fa-circle-info" aria-hidden="true"></i>
                    <span><?= h(sprintf(__('A value reported by at most %1$s'
                        . ' and sighted by %2$s stays at most %3$s, whatever'
                        . ' its points. Set under Thresholds → The'
                        . ' thin-record clamp.'),
                        sprintf(__n('one organisation', '%s organisations',
                            $clamp['voices']), $clamp['voices']),
                        $clamp['sightings'] == 0
                            ? __('nobody else')
                            : sprintf(__n('at most one other organisation',
                                'at most %s other organisations',
                                $clamp['sightings']), $clamp['sightings']),
                        isset($bands[$clamp['band']])
                            ? $bands[$clamp['band']]
                            : $clamp['band'])) ?></span>
                </p>
            <?php endif; ?>
        </div>
        <div class="sig-pop-col" data-col="b">
            <h4><?= h(__('Which way a value leans is decided apart')) ?></h4>
            <p><?= h(__('Harmful or harmless is settled by counting'
                . ' organisations: those that flag the value for detection'
                . ' against those that call it a false positive. Raising a'
                . ' weight here does not outvote them.')) ?></p>
            <p><?= h(__('The four rows marked')) ?>
                <span class="pill t-missing"><?= h(__('reads the value'))
                ?></span>
                <?= h(__('are about that question rather than about the'
                    . ' record, so their points are kept out of the signal'
                    . ' strength. A warninglist hit is the one that can turn'
                    . ' a reading contested by its points.')) ?></p>
            <h4><?= h(__('Reading a row')) ?></h4>
            <dl class="sig-pop-sets">
                <dt><span class="kv"><k>per_…</k></span></dt>
                <dd><?= h(__('points for each item counted: each'
                    . ' organisation, each feed, each month.')) ?></dd>
                <dt><span class="kv"><k>cap</k></span></dt>
                <dd><?= h(__('the most the signal can add, however much'
                    . ' evidence there is.')) ?></dd>
                <dt><span class="kv"><k>-4</k></span></dt>
                <dd><?= h(__('a negative number takes points off: the value'
                    . ' lacks something.')) ?></dd>
                <dt><span class="sig-tag is-mult"><?= h(__('trust weighted'))
                    ?></span></dt>
                <dd><?= h(__('scaled by the grades you give organisations'
                    . ' under Sources & reputation.')) ?></dd>
            </dl>
        </div>
        <div class="sig-pop-col" data-col="c">
            <h4><?= h(__('Try it')) ?></h4>
            <ul class="sig-pop-recipes">
                <li>
                    <span class="want"><?= h(__('Change one number at a'
                        . ' time')) ?></span>
                    <span class="do"><?= h(__('The value on the right is'
                        . ' rescored as soon as you leave the box, and the'
                        . ' last column shows what each signal now gives it.'
                        . ' Nothing is kept until you save.')) ?></span>
                </li>
                <li>
                    <span class="want"><?= h(__('Switch a signal off'))
                        ?></span>
                    <span class="do"><?= h(__('Untick its box. It stops'
                        . ' counting; its settings are kept.')) ?></span>
                </li>
                <li>
                    <span class="want"><?= h(__('Try another value')) ?></span>
                    <span class="do"><?= h(__('Put one on the bench on the'
                        . ' right: a value you know well is the quickest'
                        . ' way to see what a change does.')) ?></span>
                </li>
            </ul>
        </div>
    </div>
</div>
