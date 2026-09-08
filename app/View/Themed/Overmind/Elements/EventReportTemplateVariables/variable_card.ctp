<?php
/*
 * Bespoke card for the event report template variables index.
 *
 * Params from index_card:
 *   row       EventReportTemplateVariable — unused, everything is a section
 *   k         row index — unused here
 *   data      the scaffold data array — unused here
 *   sections  the card fields already rendered, dropped in as-is: 'selector'
 *             (mass-select checkbox), 'top' (the shared id element, so the
 *             record number looks the same here as in every other index),
 *             'title' (the token pill), 'body' (the value renderer) and
 *             'extra' (the row-action kebab).
 */
?>

<div class="d-flex flex-column h-100">

    <div class="d-flex align-items-center gap-2 p-2 border-bottom bg-body-tertiary rounded-top">
        <?= implode('', $sections['selector'] ?? []) ?>
        <?= implode('', $sections['top'] ?? []) ?>
        <?= implode('', $sections['title'] ?? []) ?>
        <div class="ms-auto"><?= implode('', $sections['extra'] ?? []) ?></div>
    </div>

    <div class="flex-grow-1 p-3">
        <?= implode('', $sections['body'] ?? []) ?>
    </div>

</div>
