<?php
/**
 * The value hover card — proposal C, *the instrument panel*.
 *
 * Shown when a reader hovers a value on an event page, an index table
 * or an object card. It answers *does this change what I do next*, and
 * it is read in about a second by somebody who does this fifty times an
 * hour, so the figures are the design and the prose is rationed to one
 * clipped line.
 *
 * **Three axes, and hue belongs to exactly one of them.** The lean owns
 * the colour — the rail, the glyph and the marked bar. Signal strength is a
 * magnitude and carries no hue at all (`value-palette.css` says why);
 * relevance is categorical and would have taken a fourth, so it is
 * drawn as a *number* opposite *last seen* and its state rides in ink
 * weight. Five hues on a 360px card is how a reader stops reading any
 * of them.
 *
 * Everything here is folded by `ValueHoverTool` from an assessment the
 * request already made. Nothing on this card is a second opinion, and
 * nothing on it costs a query the Assessment tab would not have cost.
 *
 * `38-hover-card.md` is the brief; §7 is why this proposal and not the
 * other two.
 *
 * @var array $valueIntelligence `value` and `card`, from
 *                          `ValueIntelligence::forHoverCard`
 * @var string $valueB64
 */
App::uses('ValueLean', 'Tools/ValueIntelligence');

$card = $valueIntelligence['card'];
$lean = $card['lean'];
$treatment = ValueLean::treatment($lean);

/*
 * A lean that names no state is drawn quietly — the same rule the pill
 * and the Assessment hero hold. A solid instrument light reading
 * *Contested* claims a certainty the record does not have.
 */
$quiet = ValueLean::isDefinite($lean) ? '' : ' vp-hc-quiet';

$bandLevels = array('none' => 0, 'low' => 1, 'medium' => 2, 'high' => 3);
$bandLevel = $bandLevels[$card['band']] ?? 0;

$relevance = $card['relevance'];
$relevanceLabels = array(
    'current' => __('Current'),
    'aging' => __('Aging'),
    'expired' => __('Expired'),
    'uncertain' => __('Timeline uncertain'),
);

$profileUrl = $this->Html->url(array(
    'controller' => 'values',
    'action' => 'view',
    $valueB64,
));

/*
 * The enrichment strip is fetched by the card rather than rendered with
 * it: knowing what a reader could ask costs an outbound call to the
 * modules service, and this card's cost argument is that a hover is
 * worth one assessment and nothing more.
 *
 * **Gated on the service being enabled at all**, which is a
 * `Configure` read and not a query. Without it an instance running no
 * modules would fire a request per hover whose only possible answer is
 * an empty strip — and on one where the service is configured but
 * down, that request is a timeout rather than an answer.
 *
 * The placeholder below reserves the strip's height, so the card does
 * not grow under the cursor when the answer lands. A card that moves
 * after it has been read is worse than one that waits.
 */
$enrichUrl = Configure::read('Plugin.Enrichment_services_enable')
    ? $this->Html->url(array(
        'controller' => 'values',
        'action' => 'viewHoverEnrichment',
        $valueB64,
    ))
    : null;

/*
 * The spark, drawn here rather than by a helper because the geometry is
 * the argument: sightings above the line, false positives and
 * expirations below it, and **one unit the same height on both sides**.
 * A chart where four false positives out-drew forty sightings would be
 * a worse lie than leaving them off, which is the mistake
 * `ValueStatsTool::sightingSpark`'s docblock records being made once.
 */
$sparkSvg = null;
$spark = $card['sightings']['spark'] ?? array();
if (!empty($spark)) {
    $upPeak = 0;
    $downPeak = 0;
    foreach ($spark as $column) {
        $upPeak = max($upPeak, (int)$column['sighting']);
        $downPeak = max(
            $downPeak,
            (int)$column['fp'] + (int)$column['expiration']
        );
    }
    if ($upPeak > 0 || $downPeak > 0) {
        $mid = 19.0;
        $upRoom = 16.0;
        $downRoom = 7.0;
        // One scale for both halves, so a unit is a unit either way.
        $scales = array();
        if ($upPeak > 0) {
            $scales[] = $upRoom / $upPeak;
        }
        if ($downPeak > 0) {
            $scales[] = $downRoom / $downPeak;
        }
        $scale = min($scales);
        /*
         * The most recent column, found before anything is drawn so it
         * can be drawn *out* of the support and into the lean's own
         * hue. Marking the latest activity is this card's one piece of
         * colour beyond the status light, and it is the piece a reader
         * sweeping a table actually uses: a value whose bars stop
         * eight columns from the right is a different value from one
         * whose last bar is against the edge.
         */
        $lastIndex = null;
        foreach ($spark as $i => $column) {
            if ((int)$column['sighting'] > 0
                || (int)$column['fp'] > 0
                || (int)$column['expiration'] > 0
            ) {
                $lastIndex = $i;
            }
        }
        $up = '';
        $down = '';
        $last = '';
        foreach ($spark as $i => $column) {
            $x = 3 + $i * 7.85;
            $rise = (int)$column['sighting'];
            $fall = (int)$column['fp'] + (int)$column['expiration'];
            if ($rise > 0) {
                $h = max(1.6, $rise * $scale);
                $bar = sprintf('M%.2f %.2fh5.2v%.2fh-5.2z',
                    $x, $mid - $h, $h);
                if ($i === $lastIndex) {
                    $last .= $bar;
                } else {
                    $up .= $bar;
                }
            }
            if ($fall > 0) {
                $h = max(1.6, $fall * $scale);
                $down .= sprintf('M%.2f %.2fh5.2v%.2fh-5.2z',
                    $x, $mid + 0.9, $h);
            }
        }
        $sparkSvg = array(
            'up' => $up,
            'down' => $down,
            'last' => $last,
            'lastX' => $lastIndex === null
                ? null
                : 3 + $lastIndex * 7.85,
            'mid' => $mid,
        );
    }
}

/*
 * What the spark's left edge stands for. Named rather than left to the
 * reader to divide ninety by forty — and taken off the column the tool
 * dated, so the caption cannot claim a span the bars do not cover.
 */
$sparkFrom = null;
if (!empty($spark) && !empty($spark[0]['from'])) {
    $sparkFrom = date('M Y', strtotime($spark[0]['from']));
}
?>
<article class="vp-hc<?= h($quiet) ?> vp-hc-lean-<?= h($treatment['slug']) ?>"
         style="--vp-hc-color: <?= h($treatment['colour']) ?>;"
         data-vp-hc-value="<?= h($valueB64) ?>">
    <span class="vp-hc-rail" aria-hidden="true"></span>
    <div class="vp-hc-panel">

        <div class="vp-hc-sec vp-hc-head">
            <div class="vp-hc-value"><?= h($card['value']) ?></div>
            <?php if (!empty($card['types']['shown'])): ?>
                <div class="vp-hc-types">
                    <?php foreach ($card['types']['shown'] as $type): ?>
                        <span class="vp-hc-type"><?= h($type['type']) ?><span
                            class="vp-hc-type-n"><?= h($type['count']) ?></span></span>
                    <?php endforeach; ?>
                    <?php if ($card['types']['more'] > 0): ?>
                        <span class="vp-hc-type vp-hc-type-more"
                              title="<?= h(__n(
                                  '%s further type',
                                  '%s further types',
                                  $card['types']['more'],
                                  $card['types']['more']
                              )) ?>">+<?= h($card['types']['more']) ?></span>
                    <?php endif; ?>
                </div>
            <?php endif; ?>
        </div>

        <div class="vp-hc-sec vp-hc-status">
            <i class="vp-hc-ico <?= h($treatment['icon']) ?>"
               aria-hidden="true"></i>
            <span class="vp-hc-lean"><?= h($treatment['label']) ?></span>
            <span class="vp-hc-band" title="<?= h(sprintf(
                __('Signal-strength band: %s'),
                $card['band']
            )) ?>">
                <span class="vp-hc-k"><?= h(__('Signal strength')) ?></span>
                <?php if ($card['signal_strength'] === null): ?>
                    <span class="vp-hc-band-n vp-hc-absent">&mdash;</span>
                <?php else: ?>
                    <span class="vp-hc-band-n"><?= h($card['signal_strength']) ?></span>
                <?php endif; ?>
                <span class="vp-hc-segs" aria-hidden="true">
                    <?php for ($i = 1; $i <= 3; $i++): ?>
                        <span class="vp-hc-seg<?=
                            $i <= $bandLevel ? ' vp-hc-on' : '' ?>"></span>
                    <?php endfor; ?>
                </span>
            </span>
        </div>

        <?php if ($card['warninglist'] !== null): ?>
            <?php $hit = $card['warninglist']; ?>
            <div class="vp-hc-sec vp-hc-alert">
                <div class="vp-hc-alert-hd">
                    <span class="vp-hc-led" aria-hidden="true"></span>
                    <span class="vp-hc-alert-k"><?= h(__('Warninglist')) ?></span>
                    <span class="vp-hc-alert-cat"><?= h(__($hit['category_label'])) ?></span>
                    <?php if (!empty($hit['version'])): ?>
                        <span class="vp-hc-alert-v">v<?= h($hit['version']) ?></span>
                    <?php endif; ?>
                </div>
                <div class="vp-hc-alert-n"><?= h($hit['name']) ?><?php
                    if (!empty($hit['match'])): ?><span
                        class="vp-hc-alert-m"> &mdash; <?= h($hit['match']) ?></span><?php
                    endif; ?></div>
                <?php if (!empty($hit['note'])): ?>
                    <div class="vp-hc-alert-s"><?= h(__($hit['note'])) ?></div>
                <?php endif; ?>
            </div>
        <?php endif; ?>

        <div class="vp-hc-sec vp-hc-read">
            <div class="vp-hc-cell">
                <div class="vp-hc-k"><?= h(__('Last seen')) ?></div>
                <?php if ($card['seen']['last']['recorded']): ?>
                    <div class="vp-hc-n"><?= h($card['seen']['last']['ago']) ?></div>
                    <div class="vp-hc-s"><?= h($card['seen']['last']['date']) ?></div>
                <?php else: ?>
                    <div class="vp-hc-n vp-hc-absent"><?= h(__('Not recorded')) ?></div>
                    <div class="vp-hc-s">&nbsp;</div>
                <?php endif; ?>
            </div>
            <div class="vp-hc-cell vp-hc-cell-r">
                <div class="vp-hc-k"><?= h(__('Runway')) ?></div>
                <?php if ($relevance['runway_days'] === null): ?>
                    <div class="vp-hc-n vp-hc-absent">&mdash;</div>
                <?php else: ?>
                    <div class="vp-hc-n"><?= h($relevance['runway_days']) ?><span
                        class="vp-hc-u">d</span></div>
                <?php endif; ?>
                <div class="vp-hc-s vp-hc-state vp-hc-state-<?= h($relevance['state']) ?>">
                    <?= h($relevanceLabels[$relevance['state']]
                        ?? $relevance['state']) ?>
                </div>
            </div>
            <div class="vp-hc-first">
                <span class="vp-hc-k"><?= h(__('First seen')) ?></span>
                <?php if ($card['seen']['first']['recorded']): ?>
                    <span class="vp-hc-first-v"><?= h($card['seen']['first']['date']) ?></span>
                    <span class="vp-hc-first-s"><?= h($card['seen']['first']['ago']) ?></span>
                <?php else: ?>
                    <span class="vp-hc-first-v vp-hc-absent"><?= h(__('Not recorded')) ?></span>
                    <span class="vp-hc-first-s"><?= h(__('no occurrence you can see')) ?></span>
                <?php endif; ?>
            </div>
        </div>

        <div class="vp-hc-sec vp-hc-tiles">
            <?php
            $tiles = array(
                array('n' => $card['counts']['orgs'], 'k' => __('Orgs')),
                array('n' => $card['counts']['events'], 'k' => __('Events')),
                array('n' => $card['counts']['occurrences'],
                    'k' => __('Occurrences')),
                array('n' => $card['counts']['sightings'],
                    'k' => __('Sightings')),
            );
            foreach ($tiles as $tile):
                /*
                 * `null` is *not read* and `0` is *none*. The hot tier
                 * never fetched the sighting rows, and a zero there
                 * would be the card inventing an answer the engine
                 * declined to look for.
                 */
                $absent = $tile['n'] === null;
                $zero = !$absent && (int)$tile['n'] === 0;
                ?>
                <div class="vp-hc-tile<?= $zero ? ' vp-hc-tile-zero' : '' ?>">
                    <span class="vp-hc-tile-n<?= $absent
                        ? ' vp-hc-absent' : '' ?>"><?=
                        $absent ? '&mdash;' : h($tile['n']) ?></span>
                    <span class="vp-hc-tile-k"><?= h($tile['k']) ?></span>
                </div>
            <?php endforeach; ?>
        </div>

        <div class="vp-hc-sec vp-hc-trace">
            <?php if ($sparkSvg !== null): ?>
                <svg class="vp-hc-spark" viewBox="0 0 320 30" role="img"
                     aria-label="<?= h(sprintf(
                         __('Sighting activity over 90 days: %s reports,'
                             . ' %s of them false positives.'),
                         $card['sightings']['total'],
                         $card['sightings']['fp']
                     )) ?>">
                    <path class="vp-hc-spark-mid" d="M3 <?= h($sparkSvg['mid'] + 0.5) ?>H317"
                          shape-rendering="crispEdges"/>
                    <?php if ($sparkSvg['up'] !== ''): ?>
                        <path class="vp-hc-spark-up" d="<?= h($sparkSvg['up']) ?>"/>
                    <?php endif; ?>
                    <?php if ($sparkSvg['down'] !== ''): ?>
                        <path class="vp-hc-spark-dn" d="<?= h($sparkSvg['down']) ?>"/>
                    <?php endif; ?>
                    <?php if ($sparkSvg['lastX'] !== null): ?>
                        <path class="vp-hc-spark-cur"
                              d="M<?= h(round($sparkSvg['lastX'] + 2.6, 2)) ?> 1V29"/>
                    <?php endif; ?>
                    <?php if ($sparkSvg['last'] !== ''): ?>
                        <path class="vp-hc-spark-last" d="<?= h($sparkSvg['last']) ?>"/>
                    <?php endif; ?>
                </svg>
                <div class="vp-hc-trace-ft">
                    <span><?= h($sparkFrom) ?></span>
                    <span class="vp-hc-trace-rt">
                        <?php if ($card['sightings']['fp'] > 0): ?>
                            <span class="vp-hc-lg"><span class="vp-hc-mk-dn"
                                aria-hidden="true"></span><?= h(sprintf(
                                    __('%s FP'),
                                    $card['sightings']['fp']
                                )) ?></span>
                        <?php endif; ?>
                        <?php if (!empty($card['sightings']['last'])): ?>
                            <span class="vp-hc-lg"><span class="vp-hc-mk-now"
                                aria-hidden="true"></span><?=
                                h($card['sightings']['last']) ?></span>
                        <?php endif; ?>
                    </span>
                </div>
            <?php elseif ($card['sightings'] === null): ?>
                <div class="vp-hc-null">
                    <span class="vp-hc-null-t"><?=
                        h(__('Sightings not read — this value'
                            . ' over-correlates')) ?></span>
                </div>
            <?php else: ?>
                <div class="vp-hc-null">
                    <span class="vp-hc-null-t"><?=
                        h(__('No sightings recorded')) ?></span>
                </div>
            <?php endif; ?>
        </div>

        <?php if (!empty($card['signals'])): ?>
            <?php /*
             * One section, not one per row: the section's padding and
             * the rule above it are the fixed cost here, and paying
             * them per row would cost more than the rows do.
             */ ?>
            <div class="vp-hc-sec vp-hc-whys">
                <?php foreach ($card['signals'] as $why): ?>
                    <div class="vp-hc-why vp-hc-why-<?= h($why['direction']) ?>">
                        <i class="vp-hc-why-ico fas fa-caret-<?=
                            $why['direction'] === 'down'
                                ? 'down' : 'up' ?>" aria-hidden="true"></i>
                        <span class="vp-hc-why-t"><?= h($why['text']) ?></span>
                        <span class="vp-hc-why-w"><?= h(sprintf(
                            '%+d',
                            $why['contribution']
                        )) ?></span>
                    </div>
                <?php endforeach; ?>
            </div>
        <?php elseif (!empty($card['summary'])): ?>
            <?php /*
             * The generated sentence, where there is no signal to show
             * instead. On a value nothing records it reads *Nothing you
             * can see records this value, so there is nothing to
             * assess* — which is a complete answer, and the reason this
             * branch is prose rather than an empty row.
             */ ?>
            <div class="vp-hc-sec vp-hc-why vp-hc-why-full vp-hc-why-null">
                <i class="vp-hc-why-ico fas fa-minus" aria-hidden="true"></i>
                <span class="vp-hc-why-t"><?= h($card['summary']) ?></span>
            </div>
        <?php endif; ?>

        <?php if ($enrichUrl !== null): ?>
            <?php /*
             * Replaced wholesale by what the strip endpoint returns,
             * or removed where it returns nothing. Skeleton rows rather
             * than a spinner, so the card keeps its height when the
             * answers land; the script matches their number to the
             * last section it drew.
             */ ?>
            <div class="vp-hc-sec vp-hc-enr vp-hc-enr-wait"
                 data-vp-hc-enrich="<?= h($enrichUrl) ?>"
                 role="status"
                 aria-label="<?= h(__('Loading enrichment')) ?>">
                <div class="vp-hc-enr-hd">
                    <span class="vp-hc-k"><?= h(__('Enrichment')) ?></span>
                </div>
                <div class="vp-hc-enr-rows">
                <?php foreach (array(array(78, 132), array(46, 96)) as $w): ?>
                    <div class="vp-hc-enr-row vp-hc-enr-skel">
                        <span class="vp-hc-enr-mod"><span class="vp-hc-enr-bar"
                            style="width:<?= $w[0] ?>px"></span></span>
                        <span class="vp-hc-enr-ans"><span class="vp-hc-enr-bar"
                            style="width:<?= $w[1] ?>px"></span></span>
                    </div>
                <?php endforeach; ?>
                </div>
            </div>
        <?php endif; ?>

        <div class="vp-hc-sec vp-hc-foot">
            <?php if ($card['galaxy'] !== null): ?>
                <span class="vp-hc-gx">
                    <?= $this->TagChip->cluster(array(
                        'value' => $card['galaxy']['name'],
                        'galaxy' => isset($card['galaxy']['galaxy'])
                            ? $card['galaxy']['galaxy']
                            : '',
                    ), array('display' => 'leaf')) ?>
                    <?php if (!empty($card['galaxy']['sub_category'])): ?>
                        <span class="vp-hc-gx-t"><?= h($card['galaxy']['sub_category']) ?></span>
                    <?php endif; ?>
                    <?php if ($card['galaxy']['more'] > 0): ?>
                        <span class="vp-hc-gx-more">+<?=
                            h($card['galaxy']['more']) ?></span>
                    <?php endif; ?>
                </span>
            <?php else: ?>
                <span class="vp-hc-gx"></span>
            <?php endif; ?>
            <a class="vp-hc-open" href="<?= h($profileUrl) ?>">
                <i class="vp-hc-open-ico misp-icon misp-icon-value-intelligence misp-simple" aria-hidden="true"></i>
                <?= h(__('Open intelligence')) ?>
                <i class="fas fa-angle-right" aria-hidden="true"></i>
            </a>
        </div>

    </div>
</article>
