<?php
/**
 * One section of the document: its blurb, then its blocks.
 *
 * Five block kinds and no section-specific form code — the view-model
 * already decided what each section is made of, and a template that
 * knew better would be a second opinion about the same document.
 *
 * Two garnishes are section-specific and deliberately so: the relevance
 * pane draws the curve its numbers describe, and the signals pane says
 * what is left in the palette.
 *
 * @var array $section
 * @var bool $editable
 * @var bool $open
 * @var array|null $ledger
 * @var string|null $benchValue
 * @var array|null $marks
 * @var array|null $runway The bench value's relevance, for the curve
 * @var string|null $lean The bench value's lean, which says which way
 *                        the palette's direction pair points
 */
$ledger = isset($ledger) ? $ledger : array();
$benchValue = isset($benchValue) ? $benchValue : null;
$marks = isset($marks) ? $marks : array();
$runway = isset($runway) ? $runway : null;
$lean = isset($lean) ? $lean : null;

$blurb = trim($section['blurb']);
$rest = '';
if (preg_match('/^(.+?[.!?])\s+(.*)$/s', $blurb, $m)) {
    $blurb = $m[1];
    $rest = $m[2];
}

$available = 0;
$configured = 0;
foreach ($section['blocks'] as $block) {
    if ($block['kind'] !== 'items') {
        continue;
    }
    foreach ($block['items'] as $item) {
        $configured++;
        if ($item['state'] === 'available') {
            $available++;
        }
    }
}
?>
<section class="wb-sec <?= $open ? 'is-open' : '' ?>"
         data-sec="<?= h($section['id']) ?>">
    <div class="wb-sec-head">
        <div>
            <p class="wb-h">
                <?= h($section['title']) ?>
                <?php if (!empty($section['axis'])): ?>
                    <span class="wb-ax"><?= h($section['axis']) ?></span>
                <?php endif; ?>
            </p>
            <p class="wb-blurb">
                <?= h($blurb) ?>
                <?php if (!empty($section['primer'])): ?>
                    <button type="button" class="sig-more"
                            data-ap-help aria-haspopup="dialog"
                            aria-expanded="false">
                        <i class="fa-solid fa-circle-question"
                           aria-hidden="true"></i><?=
                        h(__('How signals add up')) ?>
                    </button>
                    <template class="sig-help-tpl"><?=
                        $this->element('AnalystProfiles/signal_primer', array(
                            'primer' => $section['primer'],
                        )) ?></template>
                <?php elseif ($rest !== ''): ?>
                    <a href="#" class="wb-i" onclick="return false;"
                       title="<?= h($rest) ?>">i</a>
                <?php endif; ?>
            </p>
        </div>
        <?php if ($section['id'] === 'signals' && $configured > 0): ?>
            <div class="text-end">
                <p class="wb-sub mt-1 mb-0" style="max-width:20rem">
                    <?= $available === 0
                        ? h(__('Every signal this instance has is already'
                            . ' in this profile.'))
                        : h(sprintf(__n(
                            '%s signal this instance has is not in this'
                                . ' profile.',
                            '%s signals this instance has are not in this'
                                . ' profile.',
                            $available
                        ), $available)) ?>
                </p>
            </div>
        <?php endif; ?>
    </div>

    <?php foreach ($section['blocks'] as $block): ?>
        <?php if ($block['kind'] === 'items'): ?>
            <?= $this->element('AnalystProfiles/block_items', array(
                'block' => $block,
                'editable' => $editable,
                'sectionId' => $section['id'],
                'ledger' => $ledger,
                'benchValue' => $benchValue,
                'lean' => $lean,
            )) ?>
        <?php elseif ($block['kind'] === 'fields'): ?>
            <?= $this->element('AnalystProfiles/block_fields', array(
                'block' => $block,
                'editable' => $editable,
            )) ?>
        <?php elseif ($block['kind'] === 'map'): ?>
            <?php $curve = $section['id'] === 'relevance'
                && $block['id'] === 'ttl_buckets'; ?>
            <?php if ($curve): ?><div class="ttl-grid"><div class="ttl-buckets"><?php endif; ?>
            <?= $this->element('AnalystProfiles/block_map', array(
                'block' => $block,
                'editable' => $editable,
            )) ?>
            <?php if ($curve): ?>
                </div>
                <?= $this->element('AnalystProfiles/ttl_curve', array(
                    'block' => $block,
                    'section' => $section,
                    'runway' => $runway,
                )) ?>
                </div>
            <?php endif; ?>
        <?php elseif ($block['kind'] === 'order'): ?>
            <?= $this->element('AnalystProfiles/block_order', array(
                'block' => $block,
                'editable' => $editable,
            )) ?>
        <?php elseif ($block['kind'] === 'strip'): ?>
            <?= $this->element('AnalystProfiles/block_strip', array(
                'strip' => $block,
                'marks' => $marks,
            )) ?>
        <?php endif; ?>
    <?php endforeach; ?>
</section>
