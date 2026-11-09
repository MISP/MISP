<?php
/**
 * One section of the document: its blurb, then its blocks.
 *
 * Five block kinds and no section-specific form code — the view-model
 * already decided what each section is made of, and a template that
 * knew better would be a second opinion about the same document.
 *
 * Three garnishes are section-specific and deliberately so: the
 * relevance pane draws the curve its numbers describe, the lean draws
 * its share between contested and leans, and the signals pane says what
 * is left in the palette.
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
 * @var bool $compact Signals on one line each, explained behind their help
 * @var bool $mayEdit Whether the reader may edit: a `live` block is then
 *                    drawn with its inputs even on a read page
 * @var array|null $axes The bench value's readings, for the assessment card
 */
$ledger = isset($ledger) ? $ledger : array();
$benchValue = isset($benchValue) ? $benchValue : null;
$marks = isset($marks) ? $marks : array();
$runway = isset($runway) ? $runway : null;
$lean = isset($lean) ? $lean : null;
$compact = !empty($compact);
$mayEdit = !empty($mayEdit);
$axes = isset($axes) ? $axes : null;
$live = function (array $block) use ($editable, $mayEdit) {
    return !$editable && $mayEdit && !empty($block['live']);
};

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
    <div class="wb-sec-head">
        <div>
            <p class="wb-h wb-sec-title">
                <?= h($section['title']) ?>
                <?php if (!empty($section['axes'])): ?>
                    <?= $this->element('AnalystProfiles/axis_badges', array('axes' => $section['axes'])) ?>
                <?php elseif (!empty($section['axis'])): ?>
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

    <?php if (!empty($section['guide'])): ?>
        <?php $guide = $section['guide']; ?>
        <details class="wb-guide">
            <summary class="wb-guide-h">
                <i class="fa-solid fa-sliders" aria-hidden="true"></i>
                <?= h($guide['title']) ?>
                <i class="fa-solid fa-chevron-down wb-guide-caret" aria-hidden="true"></i>
            </summary>
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
        </details>
    <?php endif; ?>

    <?php
    $renderBlock = function (array $block) use (
        $section, $editable, $ledger, $benchValue, $lean, $marks, $runway,
        $compact, $live, $axes
    ) {
        $editable = $editable || $live($block);
        if (($block['display'] ?? '') === 'assessment') {
            return $this->element('AnalystProfiles/assessment_card', array(
                'block' => $block,
                'editable' => $editable,
                'axes' => $axes,
                'benchValue' => $benchValue,
            ));
        }
        if (($block['display'] ?? '') === 'bands') {
            return $this->element('AnalystProfiles/band_board', array(
                'block' => $block,
                'marks' => $marks,
                'editable' => $editable,
            ));
        }
        if (($block['display'] ?? '') === 'grade_caps') {
            return $this->element('AnalystProfiles/grade_caps', array(
                'block' => $block,
                'editable' => $editable,
            ));
        }
        if (($block['display'] ?? '') === 'scale') {
            return $this->element('AnalystProfiles/grade_scale', array(
                'block' => $block,
                'editable' => $editable,
            ));
        }
        if (($block['display'] ?? '') === 'rules') {
            return $this->element('AnalystProfiles/exclusion_rules', array(
                'block' => $block,
                'editable' => $editable,
                'benchValue' => $benchValue,
                'lean' => $lean,
                'ledger' => $ledger,
            ));
        }
        if (($block['display'] ?? '') === 'reuse') {
            return $this->element('AnalystProfiles/reuse_window', array(
                'block' => $block,
                'editable' => $editable,
            ));
        }
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
            $fields = $this->element('AnalystProfiles/block_fields', array(
                'block' => $block,
                'editable' => $editable,
            ));
            if ($section['id'] === 'relevance' && $block['id'] === 'decay') {
                // The curve the two numbers make, beside them, over the shortest bucket.
                foreach ($section['blocks'] as $buckets) {
                    if ($buckets['id'] !== 'ttl_buckets') {
                        continue;
                    }
                    return '<div class="ttl-grid"><div class="ttl-fields">' . $fields
                        . '</div>' . $this->element('AnalystProfiles/ttl_curve', array(
                            'block' => $buckets,
                            'section' => $section,
                            'runway' => $runway,
                        )) . '</div>';
                }
            }
            if ($section['id'] !== 'thresholds' || $block['id'] !== 'lean') {
                return $fields;
            }
            // The gauge under the share it draws, before the settings that follow it.
            $share = $block;
            $share['fields'] = array_slice($block['fields'], 0, 1);
            $rest = array('fields' => array_slice($block['fields'], 1),
                'live' => !empty($block['live']));
            return $this->element('AnalystProfiles/block_fields', array(
                    'block' => $share,
                    'editable' => $editable,
                )) . $this->element('AnalystProfiles/lean_gauge',
                    array('block' => $block))
                . (empty($rest['fields']) ? '' : $this->element('AnalystProfiles/block_fields', array(
                    'block' => $rest,
                    'editable' => $editable,
                )));
        }
        if ($block['kind'] === 'map') {
            return $this->element('AnalystProfiles/block_map', array(
                'block' => $block,
                'editable' => $editable,
            ));
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
        <div class="card ap-blk wb-block" data-ap-block="<?= h($block['id']) ?>"
             data-ap-kind="<?= h($block['kind']) ?>"<?= $live($block) ? ' data-ap-live' : '' ?>>
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
                <?php // One card already: the folded blocks are its parts, not cards of their own. ?>
                <?php foreach ($folded as $block): ?>
                    <div class="ap-blk-part wb-block"
                         data-ap-block="<?= h($block['id']) ?>"
                         data-ap-kind="<?= h($block['kind']) ?>"<?= $live($block) ? ' data-ap-live' : '' ?>>
                        <?= $renderBlock($block) ?>
                    </div>
                <?php endforeach; ?>
            </div>
        </details>
    <?php endif; ?>
</section>
