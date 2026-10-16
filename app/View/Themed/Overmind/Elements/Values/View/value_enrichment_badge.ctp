<?php
/**
 * One module's answer, in three chips or a number.
 *
 * **Two callers and one output.** The Overview panel includes this for
 * every module the store already holds an answer for, and
 * `ValuesController::viewEnrichmentBadge` renders it on its own for
 * every module that fired on arrival. The fragment is the same either
 * way, which is what stops a chip drawn on page load and the same chip
 * drawn four seconds later from being two different things.
 *
 * The shape rule is `ValueEnrichmentTool::chipsFor` and lives there
 * rather than here: it is arithmetic and vocabulary over a run, the
 * view draws what it decides, and a second opinion in a template is
 * how the two surfaces start to disagree.
 *
 * **A failure draws no chip.** It says so and marks itself, and the
 * panel collects the marked ones into one trailing line — an error
 * competing visually with an answer is noise in a summary. Server-side
 * that grouping is done before this is reached; for a module that
 * fired, the browser moves the row after this lands.
 *
 * When, never who: naming the analyst who ran a module would tell
 * the organisation which colleague is looking at which value.
 *
 * @var array $valueIntelligence Set when rendered as an endpoint
 * @var array $badge        Set when included by the panel
 */
$badge = isset($badge) ? $badge : array(
    'module' => $valueIntelligence['run']['module'],
    'state' => $valueIntelligence['run']['state'],
    'age' => $valueIntelligence['run']['age'],
    'chips' => $valueIntelligence['chips'],
);
$chips = $badge['chips'];
$state = (string)$badge['state'];

/*
 * Three outcomes, and the reader acts on each differently: an answer,
 * a module that answered with nothing, and one that could not answer
 * at all. `silent` is a finding rather than a failure — the module was
 * asked, it works, and it holds nothing about this value.
 */
if ($state === 'ok' && $chips['kind'] !== 'none') {
    $mark = 'ok';
} elseif ($state === 'silent') {
    $mark = 'silent';
} else {
    $mark = 'fail';
}

$token = isset($this->request->params['_Token']['key'])
    ? $this->request->params['_Token']['key']
    : '';
?>
<span class="vp-eb-res"
      data-vp-eb-res
      data-vp-eb-module="<?= h($badge['module']) ?>"
      data-vp-eb-state="<?= h($mark) ?>"
      data-vp-eb-token="<?= h($token) ?>">
    <?php if ($mark === 'ok'): ?>
        <span class="vp-e-chips vp-eb-chips">
            <?php if ($chips['kind'] === 'count'): ?>
                <?php
                /*
                 * The size and what was sized, because three relations
                 * picked out of 1,375 passive-DNS records would be
                 * three chips chosen by whichever order the module
                 * happened to send them in.
                 */
                ?>
                <span class="vp-e-chip vp-e-chip-n">
                    <span class="vp-eb-v"><?=
                        h(number_format($chips['count'])) ?></span>
                    <?php if ($chips['noun'] !== null): ?>
                        <span class="vp-eb-k"><?=
                            h($chips['noun']) ?></span>
                    <?php endif; ?>
                </span>
            <?php else: ?>
                <?php foreach ($chips['chips'] as $chip): ?>
                    <span class="vp-e-chip">
                        <span class="vp-eb-k"><?=
                            h($chip['label']) ?></span>
                        <span class="vp-eb-v"><?=
                            h($chip['value']) ?></span>
                    </span>
                <?php endforeach; ?>
                <?php if ($chips['more'] > 0): ?>
                    <?php
                    /*
                     * What the cap left out, stated rather than
                     * dropped: the panel is a summary and a reader has
                     * to know it is one. The tab holds the rest.
                     */
                    ?>
                    <span class="vp-e-chip vp-e-chip-quiet"
                          title="<?= h(__('The Enrichment tab has the'
                              . ' rest')) ?>">+<?=
                        h(number_format($chips['more'])) ?></span>
                <?php endif; ?>
            <?php endif; ?>
        </span>
    <?php elseif ($mark === 'silent'): ?>
        <span class="vp-eb-quiet"><?= h(__('nothing about this value')) ?></span>
    <?php else: ?>
        <span class="vp-eb-quiet"><?= h(__('could not answer')) ?></span>
    <?php endif; ?>

    <?php if ($badge['age'] !== null): ?>
        <span class="vp-eb-age"><?= $this->element(
            'Values/View/value_enrichment_age',
            array('askedAge' => $badge['age'])
        ) ?></span>
    <?php endif; ?>
</span>
