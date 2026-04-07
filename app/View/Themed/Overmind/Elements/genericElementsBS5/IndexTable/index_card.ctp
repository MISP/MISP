<?php
$data = $scaffold_data['data'];
?>

<div class="table-scroll row g-3" style="background: #f8f9fa;">

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
?>

<div class="ps-2 pe-2">
    <div class="card shadow-sm">

        <div class="card-body">

            <div class="row align-items-start">

                <!-- COL 1 -->
                <div class="col-auto">
                    <?= implode('', $sections['selector']) ?>
                </div>

                <!-- COL 2 -->
                <div class="col d-flex flex-column gap-1">

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
                        <hr class="my-1">
                        <div class="d-flex flex-wrap align-items-center justify-content-between gap-2">
                            <?php foreach ($sections['meta'] as $item): ?>
                                <div><?= $item ?></div>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>

                </div>

                <!-- COL 3 -->
                <div class="col-auto text-end">
                    <?= implode('', $sections['extra']) ?>
                </div>

            </div>

        </div>

    </div>
</div>

<?php endforeach; ?>

</div>