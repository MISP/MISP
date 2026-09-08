<?php

$basePath = $field['data_path'];
$template = Hash::extract($row, $basePath);

if (empty($template)) {
    return;
}

$isCard = isset($viewMode) && $viewMode === 'card';

// Optional link on the name.
$nameHtml = h($template['name'] ?? '');
if (!empty($field['url']) && !empty($template['id'])) {
    $nameHtml = '<a href="' . h(str_replace('%id%', h($template['id']), $field['url']))
        . '" class="text-decoration-none">' . $nameHtml . '</a>';
}

?>

<div class="d-flex flex-column">
    <div class="d-flex align-items-center gap-2 flex-wrap mb-0">
        <?php if (!$isCard):
            echo $this->element(
                '/genericElementsBS5/IndexTable/Fields/distribution',
                [
                    'row' => $row,
                    'field' => [
                        'data_path' => $basePath . '.distribution',
                        'display' => 'short'
                    ]
                ]
            );
            echo $this->element(
                '/genericElementsBS5/IndexTable/Fields/active',
                [
                    'row' => $row,
                    'field' => [
                        'data_path' => $basePath . '.active',
                        'title_off' => __('Inactive templates are hidden from the "From template" picker'),
                    ]
                ]
            );
        endif; ?>

        <p class="mb-0 fw-semibold" style="font-size: 1.2em;">
            <?= $nameHtml ?>
        </p>
    </div>

    <!-- Description: compact, single-line, truncated (full text on hover) -->
    <?php if (empty($field['hide_description']) && !empty($template['description'])):
        $desc = trim($template['description']);
    ?>
        <div class="text-muted fst-italic text-truncate mt-1"
             style="font-size:.8em; max-width:900px;"
             title="<?= h($desc) ?>">
            <i class="fa fa-comment opacity-50 me-1"></i><?= h($desc) ?>
        </div>
    <?php endif; ?>
</div>
