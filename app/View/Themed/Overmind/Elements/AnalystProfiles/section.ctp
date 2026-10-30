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
 * @var bool $bare The caller draws the title and blurb (the view's cards)
 * @var bool $compact Signals on one line each, explained behind their help
 */
$ledger = isset($ledger) ? $ledger : array();
$benchValue = isset($benchValue) ? $benchValue : null;
$marks = isset($marks) ? $marks : array();
$runway = isset($runway) ? $runway : null;
$lean = isset($lean) ? $lean : null;
$bare = !empty($bare);
$compact = !empty($compact);

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

$primer = '';
if (!empty($section['primer'])) {
    $primer = '<button type="button" class="sig-more" data-ap-help'
        . ' aria-haspopup="dialog" aria-expanded="false">'
        . '<i class="fa-solid fa-circle-question" aria-hidden="true"></i>'
        . h($section['primer']['label']) . '</button>'
        . '<template class="sig-help-tpl">' . $this->element(
            'AnalystProfiles/' . $section['primer']['kind'] . '_primer',
            array('primer' => $section['primer'])
        ) . '</template>';
}
$palette = '';
if ($section['id'] === 'signals' && $configured > 0) {
    $palette = $available === 0
        ? __('Every signal this instance has is already in this profile.')
        : sprintf(__n(
            '%s signal this instance has is not in this profile.',
            '%s signals this instance has are not in this profile.',
            $available
        ), $available);
}
?>
<section class="wb-sec <?= $open ? 'is-open' : '' ?>"
         data-sec="<?= h($section['id']) ?>">
    <?php if (!$bare): ?>
    <div class="wb-sec-head">
        <div>
            <p class="wb-h wb-sec-title">
                <?= h($section['title']) ?>
                <?php if (!empty($section['axis'])): ?>
                    <span class="wb-ax"><?= h($section['axis']) ?></span>
                <?php endif; ?>
            </p>
            <p class="wb-blurb">
                <?= h($blurb) ?>
                <?php if ($primer !== ''): ?>
                    <?= $primer ?>
                <?php elseif ($rest !== ''): ?>
                    <a href="#" class="wb-i" onclick="return false;"
                       title="<?= h($rest) ?>">i</a>
                <?php endif; ?>
            </p>
        </div>
        <?php if ($palette !== ''): ?>
            <div class="text-end">
                <p class="wb-sub mt-1 mb-0" style="max-width:20rem">
                    <?= h($palette) ?>
                </p>
            </div>
        <?php endif; ?>
    </div>
    <?php elseif ($primer !== '' || $palette !== ''): ?>
        <div class="wb-sec-tools">
            <?= $primer ?>
            <span class="wb-sub"><?= h($palette) ?></span>
        </div>
    <?php endif; ?>

    <?php if (!empty($section['guide']) && $bare): ?>
        <?php // A reader's page keeps the tuning advice one press away. ?>
        <details class="wb-fold wb-guide-fold">
            <summary>
                <i class="fa-solid fa-chevron-right wb-fold-caret"
                   aria-hidden="true"></i>
                <span class="wb-fold-label"><?= h($section['guide']['title']) ?></span>
            </summary>
            <div class="wb-fold-body">
                <?php if (!empty($section['guide']['intro'])): ?>
                    <p class="wb-guide-intro"><?= h($section['guide']['intro']) ?></p>
                <?php endif; ?>
                <dl class="wb-guide-list">
                    <?php foreach ($section['guide']['items'] as $item): ?>
                        <div>
                            <dt><?= h($item['symptom']) ?></dt>
                            <dd><?= h($item['remedy']) ?></dd>
                        </div>
                    <?php endforeach; ?>
                </dl>
            </div>
        </details>
    <?php elseif (!empty($section['guide'])): ?>
        <?php $guide = $section['guide']; ?>
        <div class="wb-guide">
            <p class="wb-guide-h">
                <i class="fa-solid fa-sliders" aria-hidden="true"></i>
                <?= h($guide['title']) ?>
            </p>
            <?php if (!empty($guide['intro'])): ?>
                <p class="wb-guide-intro"><?= h($guide['intro']) ?></p>
            <?php endif; ?>
            <dl class="wb-guide-list">
                <?php foreach ($guide['items'] as $item): ?>
                    <div>
                        <dt><?= h($item['symptom']) ?></dt>
                        <dd><?= h($item['remedy']) ?></dd>
                    </div>
                <?php endforeach; ?>
            </dl>
        </div>
    <?php endif; ?>

    <?php
    $renderBlock = function (array $block) use (
        $section, $editable, $ledger, $benchValue, $lean, $marks, $runway,
        $compact
    ) {
        if ($block['kind'] === 'items') {
            return $this->element('AnalystProfiles/block_items', array(
                'block' => $block,
                'editable' => $editable,
                'sectionId' => $section['id'],
                'ledger' => $ledger,
                'benchValue' => $benchValue,
                'lean' => $lean,
                'compact' => $compact,
            ));
        }
        if ($block['kind'] === 'fields') {
            return $this->element('AnalystProfiles/block_fields', array(
                'block' => $block,
                'editable' => $editable,
            ));
        }
        if ($block['kind'] === 'map') {
            $map = $this->element('AnalystProfiles/block_map', array(
                'block' => $block,
                'editable' => $editable,
            ));
            if ($section['id'] !== 'relevance'
                || $block['id'] !== 'ttl_buckets'
            ) {
                return $map;
            }
            return '<div class="ttl-grid"><div class="ttl-buckets">' . $map
                . '</div>' . $this->element('AnalystProfiles/ttl_curve', array(
                    'block' => $block,
                    'section' => $section,
                    'runway' => $runway,
                )) . '</div>';
        }
        if ($block['kind'] === 'order') {
            return $this->element('AnalystProfiles/block_order', array(
                'block' => $block,
                'editable' => $editable,
            ));
        }
        if ($block['kind'] === 'strip') {
            return $this->element('AnalystProfiles/block_strip', array(
                'strip' => $block,
                'marks' => $marks,
                'editable' => $editable,
            ));
        }
        return '';
    };
    $main = array();
    $folded = array();
    foreach ($section['blocks'] as $block) {
        if (!empty($block['advanced']) && !empty($section['fold'])) {
            $folded[] = $block;
        } else {
            $main[] = $block;
        }
    }
    ?>
    <?php foreach ($main as $block): ?>
        <div class="wb-block" data-ap-block="<?= h($block['id']) ?>">
            <?= $renderBlock($block) ?>
        </div>
    <?php endforeach; ?>

    <?php if (!empty($folded)): ?>
        <details class="wb-fold" data-ap-fold>
            <summary>
                <i class="fa-solid fa-chevron-right wb-fold-caret"
                   aria-hidden="true"></i>
                <span class="wb-fold-label"><?=
                    h($section['fold']['label']) ?></span>
                <?php if (!empty($section['fold']['summary'])): ?>
                    <span class="wb-fold-sum"><?=
                        h($section['fold']['summary']) ?></span>
                <?php endif; ?>
                <span class="wb-fold-edited"><?=
                    h(__('unsaved changes')) ?></span>
            </summary>
            <div class="wb-fold-body">
                <?php foreach ($folded as $block): ?>
                    <div class="wb-block"
                         data-ap-block="<?= h($block['id']) ?>">
                        <?= $renderBlock($block) ?>
                    </div>
                <?php endforeach; ?>
            </div>
        </details>
    <?php endif; ?>
</section>
