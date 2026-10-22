<?php
/**
 *
 * jQuery-free BS5 rewrite of app/View/Events/import_module.ctp. The form
 * itself is the Events/import_module_form element, which "Populate from…"
 * also shows inline.
 *
 * Vars: $module, $configTypes, $eventId, $event, $mayModify, $moduleError.
 */

$eventId = (int)$eventId;
?>

<?= $this->element('genericElementsBS5/Forms/modal_header', [
    'eyebrow' => __('Import module'),
    'title' => Inflector::humanize($module['name']),
    'titleIcon' => 'fas fa-puzzle-piece',
    'description' => __('Event') . ': #' . $eventId,
    'aside' => sprintf(
        '<div class="d-flex gap-2">'
            . '<button type="button" class="btn btn-outline-secondary btn-sm"'
            . ' onclick="openModalChained(\'%s/events/populateFrom/%d\');">'
            . '<i class="fas fa-arrow-left me-1"></i>%s</button>'
            . '<button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="%s"></button>'
            . '</div>',
        h($baseurl), $eventId, h(__('Back')), h(__('Close'))
    ),
]) ?>

<!-- ── BODY ─────────────────────────────────────────────────── -->
<div class="p-4">
    <?= $this->element('Events/import_module_form', [
        'idPrefix' => 'importModule',
        'moduleError' => isset($moduleError) ? $moduleError : null,
    ]) ?>
</div>
