<?php
/*
 * Card view of an index.
 *
 * Cards per row: `cards_per_row` — either count (1..6) or array of breakpoint => count.
 * Breakpoints: '' (base), sm, md, lg, xl, xxl, xxxl, xxxxl. Last two are custom.
 * `row-cols-N` class does layout work, overriding width:100%.
 *
 * Bespoke cards: `card_element` names an element rendering custom card content.
 * Scaffold keeps .card shell for layout; element gets `row`, `k`, `data`, `sections`.
 *
 * `meta` section pinned bottom: card-body.d-flex.flex-column > .row.flex-grow-1 > .col
 * gives full height; mt-auto on meta eats leftover space. All classes load-bearing.
 */
$data = $scaffold_data['data'];

$cardElement = $data['card_element'] ?? null;

$cardTiers = ['', 'sm', 'md', 'lg', 'xl', 'xxl', 'xxxl', 'xxxxl'];

$perRow = $data['cards_per_row'] ?? 1;
if (is_array($perRow)) {
    $breakpoints = array_intersect_key($perRow, array_flip($cardTiers));
} else {
    $ladder = ['' => 1, 'md' => 2, 'xl' => 3, 'xxl' => 4, 'xxxl' => 5, 'xxxxl' => 6];
    $perRow = max(1, min(6, (int)$perRow));
    $breakpoints = [];
    foreach ($ladder as $bp => $n) {
        $breakpoints[$bp] = min($n, $perRow);
    }
}

// Emit in breakpoint order whatever order the index wrote them in, and only on
// the tiers where the count actually changes.
$rowColsClass = '';
$previous = null;
foreach ($cardTiers as $bp) {
    if (!isset($breakpoints[$bp])) {
        continue;
    }
    $n = max(1, min(6, (int)$breakpoints[$bp]));
    if ($n === $previous) {
        continue;
    }
    $rowColsClass .= ' row-cols' . ($bp === '' ? '' : '-' . $bp) . '-' . $n;
    $previous = $n;
}
?>

<?php if (empty($data['data'])): ?>

<div class="d-flex flex-column align-items-center text-secondary py-5">
    <i class="fas fa-inbox fa-2x d-block mb-2"></i>
    <?= __('No items to display') ?>
</div>

<?php else: ?>

<div class="table-scroll idx-card-grid row g-3 bg-light<?= $rowColsClass ?>">

<?php foreach ($data['data'] as $k => $row): ?>

<?php
$sections = [
    'selector' => [],
    'meta' => [],
    'title' => [],
    'links' => [],
    'extra' => []
];

$cardFields = array_filter($data['fields'], function($field) {
    if (empty($field['display_in'])) {
        return true;
    }
    return in_array('card', $field['display_in']);
});

foreach ($cardFields as $column => $field) {

    $section = $field['card_section'] ?? 'extra';

    ob_start();

    if (!isset($field['requirement']) || $field['requirement']) {

        if (empty($field['element'])) {
            $valueField = $this->element(
                'genericElementsBS5/IndexTable/Fields/generic_field',
                [
                    'field' => $field,
                    'row' => $row,
                    'data_path' => $field['data_path'] ?? '',
                    'k' => $k,
                    'column' => $column
                ]
            );
        } else {
            $valueField = $this->element(
                'genericElementsBS5/IndexTable/Fields/' . $field['element'],
                [
                    'field' => $field,
                    'row' => $row,
                    'column' => $column,
                    'data_path' => $field['data_path'] ?? '',
                    'k' => $k,
                    'viewMode' => 'card',
                ]
            );
        }

        if (!empty($field['decorator'])) {
            $valueField = $field['decorator']($valueField);
        }

        echo $valueField;
    }

    $sections[$section][] = ob_get_clean();
}

/*
 * A field that renders nothing still buffers an entry, and every section below
 * only asks whether its array is empty. Drop the blanks so a field that opted
 * out for this row doesn't leave an empty flex line (or, worse, a gutter-only
 * column) eating the width of a narrow card.
 */
foreach ($sections as $section => $items) {
    $sections[$section] = array_filter($items, function ($item) {
        return trim($item) !== '';
    });
}
?>

<?php
$cardClass = '';
if (!empty($data['row_class_callable']) && is_callable($data['row_class_callable'])) {
    $cardClass = call_user_func($data['row_class_callable'], $row);
}
$cardStyle = '';
if (!empty($data['row_style_callable']) && is_callable($data['row_style_callable'])) {
    $cardStyle = call_user_func($data['row_style_callable'], $row);
}
?>
<div class="idx-card-col px-2">
    <div class="card shadow-sm idx-card h-100 <?= h($cardClass) ?>"<?= $cardStyle === '' ? '' : ' style="' . h($cardStyle) . '"' ?>>

        <?php if ($cardElement): ?>

        <?= $this->element($cardElement, [
            'row' => $row,
            'k' => $k,
            'data' => $data,
            'sections' => $sections,
        ]) ?>

        <?php else: ?>

        <div class="card-body d-flex flex-column">

            <div class="row align-items-start flex-grow-1">

                <!-- COL 1 -->
                <?php if (!empty($sections['selector'])): ?>
                    <div class="col-auto">
                        <?= implode('', $sections['selector']) ?>
                    </div>
                <?php endif; ?>

                <!-- COL 2 -->
                <div class="col d-flex flex-column gap-1 align-self-stretch">

                    <!-- Line 1 : TOP -->
                    <?php if (!empty($sections['top'])): ?>
                        <div class="d-flex flex-wrap align-items-center gap-2">
                            <?php foreach ($sections['top'] as $item): ?>
                                <div><?= $item ?></div>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>

                     <!-- Line 2 : ATTRIBUTE -->
                    <?php if (!empty($sections['attribute'])): ?>
                        <div class="d-flex flex-wrap align-items-center gap-2">
                            <?php foreach ($sections['attribute'] as $item): ?>
                                <div><?= $item ?></div>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>

                    <!-- Line 3 : TITLE -->
                    <?php if (!empty($sections['title'])): ?>
                        <div class="d-flex flex-wrap align-items-center gap-2">
                            <?php foreach ($sections['title'] as $item): ?>
                                <?= $item ?>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>

                    <!-- Line 4 : TAG -->
                    <?php if (!empty($sections['tag'])): ?>
                        <div class="d-flex flex-wrap align-items-center gap-2">
                            <?php foreach ($sections['tag'] as $item): ?>
                                <?= $item ?>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>

                    <!-- Line 5 : GALAXY -->
                    <?php if (!empty($sections['galaxy'])): ?>
                        <div class="d-flex flex-wrap align-items-center gap-2">
                            <?php foreach ($sections['galaxy'] as $item): ?>
                                <div><?= $item ?></div>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>

                    <!-- Line 6 : LINKS -->
                    <?php if (!empty($sections['links'])): ?>
                        <div class="">
                            <?= implode('', $sections['links']) ?>
                        </div>
                    <?php endif; ?>

                    <!-- META DIVIDER + META -->
                    <?php if (!empty($sections['meta'])): ?>
                        <hr class="mt-auto mb-1">
                        <div class="d-flex flex-wrap align-items-center justify-content-between gap-2">
                            <?php foreach ($sections['meta'] as $item): ?>
                                <div><?= $item ?></div>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>

                </div>

                <!-- COL 3 -->
                <?php if (!empty($sections['extra'])): ?>
                    <div class="col-auto text-end">
                        <?= implode('', $sections['extra']) ?>
                    </div>
                <?php endif; ?>

            </div>

        </div>

        <?php endif; ?>

    </div>
</div>

<?php endforeach; ?>

</div>

<?php endif; ?>