<?php
/**
 * The hover card's enrichment section: what the modules said, one row
 * each.
 *
 * **Fetched by the card, never with it.** Knowing what a reader could
 * ask costs an outbound call to the modules service
 * (`enrichmentCatalogue`), and the card's whole cost argument is that a
 * hover is worth one assessment and nothing more. So the card paints
 * without this, asks for it, and grows once — and modules that have to
 * be run fill in after that, which is why each chip is a name with a
 * slot rather than a finished string.
 *
 * **The same firing contract as the Overview panel.** The plan travels
 * on the element as `data-vp-eb-fire`, five go at a time, and each is
 * `mode=auto` at the endpoint that decides the gate and the reuse
 * window again when it lands. What differs is `shape=chip`: the panel
 * wants every chip a module returned and the card wants the headline.
 *
 * When, never who: naming the analyst who ran a module would tell the
 * organisation which colleague is looking at which value.
 *
 * @var array $valueIntelligence `panel`, from
 *     `ValueIntelligence::forEnrichmentPanel`
 * @var string $valueB64
 */
$panel = $valueIntelligence['panel'];
if (empty($panel['present']) || empty($panel['modules'])) {
    /*
     * Nothing known and nothing askable. The card renders no section at
     * all rather than an empty one — a strip reading *no enrichment* on
     * every value of every instance that never enriched anything is the
     * permanently empty row the Overview's own guard exists to refuse.
     */
    return;
}

$baseurl = isset($baseurl) ? $baseurl : Configure::read('MISP.baseurl');
$token = isset($this->request->params['_Token']['key'])
    ? $this->request->params['_Token']['key']
    : '';

/*
 * One row a module, four rows at most, the rest counted. The cap is the
 * firing set as well as the drawn set, so raising it raises how many
 * modules a single hover may ask.
 */
$cap = 4;
$shown = array_slice($panel['modules'], 0, $cap);
$more = max(0, count($panel['modules']) - $cap);

/*
 * Only the modules still on the strip may be fired. A plan naming one
 * the cap dropped would send a request whose answer has nowhere to
 * land, and the lane would spend itself writing into nothing.
 */
$names = array();
foreach ($shown as $entry) {
    $names[$entry['module']] = true;
}
$fire = array();
foreach ($panel['fire'] as $one) {
    if (isset($names[$one['module']])) {
        $fire[] = $one;
    }
}
?>
<div class="vp-hc-sec vp-hc-enr"
     data-vp-ebadge
     data-vp-eb-shape="chip"
     data-vp-eb-token="<?= h($token) ?>"
     data-vp-eb-fire="<?= h(json_encode($fire)) ?>"
     data-vp-eb-max="5"
     data-vp-eb-url="<?= h($baseurl . '/values/viewEnrichmentBadge/'
        . $valueB64) ?>">
    <div class="vp-hc-enr-hd">
        <span class="vp-hc-k"><?= h(__('Enrichment')) ?></span>
        <?php if ($more > 0): ?>
            <span class="vp-hc-enr-more"
                  title="<?= h(__('Shown on the Enrichment tab')) ?>"><?=
                h(__n(
                    '+%s more module',
                    '+%s more modules',
                    $more,
                    $more
                )) ?></span>
        <?php endif; ?>
    </div>
    <div class="vp-hc-enr-rows">
    <?php foreach ($shown as $entry): ?>
        <div class="vp-hc-enr-row" data-vp-eb-row="<?= h($entry['module']) ?>">
            <span class="vp-hc-enr-mod" title="<?= h($entry['module']) ?>"><?=
                h($entry['module']) ?></span>
            <span class="vp-hc-enr-ans" data-vp-eb-slot>
                <?php if ($entry['pending'] === 'fire'): ?>
                    <span class="vp-hce-v vp-hce-ask">
                        <i class="fas fa-circle-notch fa-spin"
                           aria-hidden="true"></i>
                        <?= h(__('asking')) ?>
                    </span>
                <?php elseif ($entry['pending'] === 'in_flight'): ?>
                    <?php
                    /*
                     * Somebody else's request is about to write this
                     * answer, so nothing is sent: asking now would start a
                     * second query rather than wait for the first.
                     */
                    ?>
                    <span class="vp-hce-v vp-hce-wait"><?=
                        h(__('being asked')) ?></span>
                <?php else: ?>
                    <?= $this->element(
                        'Values/View/value_enrichment_chip',
                        array('badge' => $entry)
                    ) ?>
                <?php endif; ?>
            </span>
        </div>
    <?php endforeach; ?>
    </div>
</div>
