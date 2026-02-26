<?php
$data = $scaffold_data['data'];
?>

<div class="row g-3">

<?php foreach ($data['data'] as $k => $row): ?>

<?php
$sections = [
    'selector' => [],
    'meta' => [],
    'title' => [],
    'links' => [],
    'extra' => []
];

foreach ($data['fields'] as $column => $field) {

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
                    'k' => $k
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

<div class="col-12">
    <div class="card shadow-sm">

        <div class="card-body">

            <div class="row align-items-start">

                <!-- COL 1 -->
                <div class="col-auto">
                    <?= implode('', $sections['selector']) ?>
                </div>

                <!-- COL 2 -->
                <div class="col">

                    <!-- Ligne 1 -->
                    <?php if (!empty($sections['meta'])): ?>
                        <div class="d-flex align-items-center gap-2 mb-2">
                            <?= implode('', $sections['meta']) ?>
                        </div>
                    <?php endif; ?>

                    <!-- Ligne 2 -->
                    <?php if (!empty($sections['title'])): ?>
                        <div class="d-flex align-items-center gap-2 mb-2 fs-3 fw-bold">
                            <?= implode(' - ', array_filter($sections['title'])) ?>
                        </div>
                    <?php endif; ?>

                    <!-- Ligne 3 -->
                    <?php if (!empty($sections['tag'])): ?>
                        <div class="d-flex align-items-center flex-wrap gap-2 mb-2">
                            <?= implode(' - ', array_filter($sections['tag'])) ?>
                        </div>
                    <?php endif; ?>

                    <!-- Ligne 4 -->
                    <?php if (!empty($sections['galaxy'])): ?>
                        <div class="d-flex align-items-center flex-wrap gap-2 mb-2">
                            <?= implode(' - ', array_filter($sections['galaxy'])) ?>
                        </div>
                    <?php endif; ?>

                    <!-- Ligne 3 -->
                    <?php if (!empty($sections['links'])): ?>
                        <div class="">
                            <?= implode('', $sections['links']) ?>
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