<?php
/**
 * One section of a profile as a card of a tab: its title and first
 * sentence as a summary the reader folds, its blocks below. In the
 * editor the summary also says when the section holds unsaved changes.
 *
 * @var array $section
 * @var bool $editable
 * @var bool $open
 * @var string $count What the summary's pill says
 * @var array $readings AnalystProfileFormTool::benchReadings()
 * @var string|null $benchValue
 */
$icons = array(
    'signals' => 'wave-square',
    'thresholds' => 'gauge',
    'escalations' => 'scale-balanced',
    'exclusions' => 'ban',
    'relevance' => 'clock-rotate-left',
    'reference' => 'shield-halved',
    'enrichment' => 'puzzle-piece',
    'context' => 'eye',
    'galaxies' => 'crosshairs',
);
$blurb = trim($section['blurb']);
$first = preg_match('/^(.+?[.!?])(\s|$)/s', $blurb, $m) ? $m[1] : $blurb;
?>
<details class="card ap-vcard" id="ap-sec-<?= h($section['id']) ?>"<?= $open ? ' open' : '' ?>>
    <summary class="ap-vcard-h">
        <span class="ap-vcard-ico" aria-hidden="true"><i class="fas fa-<?= h(
            isset($icons[$section['id']]) ? $icons[$section['id']] : 'sliders') ?>"></i></span>
        <span class="ap-vcard-t">
            <span class="ap-vcard-title"><?= h($section['title']) ?></span>
            <span class="ap-vcard-blurb"<?= $first === $blurb
                ? '' : ' title="' . h($blurb) . '"' ?>><?= h($first) ?></span>
        </span>
        <?php if ($editable): ?>
            <span class="pill t-over" data-ap-dirty-mark="<?= h($section['id']) ?>"
                  hidden><?= h(__('unsaved')) ?></span>
        <?php endif; ?>
        <span class="pill t-plain"><?= h($count) ?></span>
        <i class="fas fa-chevron-down ap-vcard-caret" aria-hidden="true"></i>
    </summary>
    <div class="ap-vcard-b">
        <?= $this->element('AnalystProfiles/section', array(
            'section' => $section,
            'editable' => $editable,
            'open' => true,
            'ledger' => $readings['ledger'],
            'benchValue' => $benchValue,
            'marks' => $readings['marks'],
            'runway' => $readings['runway'],
            'lean' => $readings['lean'],
            'bare' => true,
            'compact' => true,
        )) ?>
    </div>
</details>
