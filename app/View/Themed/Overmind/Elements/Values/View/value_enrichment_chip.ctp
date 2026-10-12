<?php
/**
 * One module's answer, reduced to a headline.
 *
 * The hover card's counterpart to `value_enrichment_badge`, and it
 * takes the same array: the badge draws every chip a module returned
 * because the Overview has a nine-column width to spend, and this draws
 * the one that answers *did this module find anything*, on the one row
 * the card gives each module.
 *
 * **It decides nothing the badge does not.** Both read
 * `ValueEnrichmentTool::chipsFor`, so a module that reads *malicious*
 * here cannot read something else one page away; what differs is how
 * much of the same answer is drawn.
 *
 * Rendered on its own by `ValuesController::viewEnrichmentBadge` when
 * the caller asks for `shape=chip`, and included by
 * `value_hover_enrichment` for the answers the store already held.
 *
 * @var array $valueIntelligence Set when rendered as an endpoint
 * @var array $badge        Set when included by the strip
 * @var string $valueB64
 */
$badge = isset($badge) ? $badge : array(
    'module' => $valueIntelligence['run']['module'],
    'state' => $valueIntelligence['run']['state'],
    'chips' => $valueIntelligence['chips'],
);
$chips = $badge['chips'];
$state = (string)$badge['state'];

/*
 * Three outcomes and a headline each. `silent` is a finding rather than
 * a failure — the module was asked, it works, and it holds nothing
 * about this value — so it says so in words rather than going quiet,
 * which on a chip would be indistinguishable from still waiting.
 */
$mark = 'ok';
$label = null;
$headline = null;
if ($state === 'ok' && $chips['kind'] === 'count') {
    /*
     * The size and what was sized. A module that returned 1,375
     * passive-DNS records has no single value worth lifting out of
     * them, and the count is the honest summary of a set.
     */
    $headline = number_format($chips['count']);
    $label = $chips['noun'];
} elseif ($state === 'ok' && $chips['kind'] === 'chips'
    && !empty($chips['chips'])
) {
    /*
     * The first chip, which is the first the module sent: the shape
     * rule already ordered them, and a second opinion about which one
     * matters would be this template deciding something
     * `ValueEnrichmentTool` decides.
     */
    $label = $chips['chips'][0]['label'];
    $headline = $chips['chips'][0]['value'];
} elseif ($state === 'silent') {
    $mark = 'silent';
    $headline = __('nothing found');
} else {
    $mark = 'fail';
    $headline = __('no answer');
}

/*
 * What the headline left behind, counted. A reader has to know the row
 * is a summary of an answer rather than the whole of one.
 */
$rest = array();
$beyond = 0;
if ($mark === 'ok' && $chips['kind'] === 'chips') {
    $rest = array_slice($chips['chips'], 1);
    $beyond = (int)$chips['more'];
}
$restCount = count($rest) + $beyond;

// A count reads number first (`1,375 domain`), a field label first (`asn 15169`).
$labelAfter = $mark === 'ok' && $chips['kind'] === 'count';
$full = $labelAfter
    ? trim($headline . ' ' . $label)
    : trim($label . ' ' . $headline);
?>
<span class="vp-hc-enr-ans">
    <span class="vp-hce-v vp-hce-<?= h($mark) ?>" title="<?= h($full) ?>">
        <?php if ($label !== null && !$labelAfter): ?>
            <span class="vp-hce-l"><?= h($label) ?></span>
        <?php endif; ?>
        <span class="vp-hce-x"><?= h($headline) ?></span>
        <?php if ($label !== null && $labelAfter): ?>
            <span class="vp-hce-l"><?= h($label) ?></span>
        <?php endif; ?>
    </span>
    <?php if ($restCount > 0): ?>
        <button type="button" class="vp-hce-more" data-vp-hce-more
                aria-expanded="false"
                title="<?= h(__('Show the rest of this answer')) ?>">+<?=
            h($restCount) ?><i class="fas fa-angle-down"
            aria-hidden="true"></i></button>
    <?php endif; ?>
</span>
<?php foreach ($rest as $chip): ?>
    <span class="vp-hc-enr-rest"
          title="<?= h($chip['label'] . ' ' . $chip['value']) ?>">
        <span class="vp-hce-l"><?= h($chip['label']) ?></span>
        <span class="vp-hce-x"><?= h($chip['value']) ?></span>
    </span>
<?php endforeach; ?>
<?php if ($beyond > 0): ?>
    <a class="vp-hc-enr-rest vp-hc-enr-rest-link" href="<?= h($this->Html->url(array(
        'controller' => 'values',
        'action' => 'view',
        $valueB64,
        '?' => array('module' => $badge['module']),
        '#' => 'tab-enrichment',
    ))) ?>"><?= h(sprintf(
        __('%s more on the Enrichment tab'),
        $beyond
    )) ?><i class="fas fa-arrow-right" aria-hidden="true"></i></a>
<?php endif; ?>
