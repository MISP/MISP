<?php
/*
 * delete_mode.ctp — what turns a Modals/confirmation_form into an in-place
 * delete: the soft / permanent switch, and the payload initDeleteConfirmations()
 * in mispOvermind.js reads to post the form through fetch() and refresh the
 * index behind the modal. Pass it as the confirmation's `bodyHtml`, with
 * `hiddenField => false`: the form's action is the POST target.
 *
 * The switch carries no name attribute. The script builds the body itself,
 * and a field the rendered form did not declare would be black-holed.
 *
 * Required params:
 *   $model  string  'Attribute' | 'Object' — the selection posts as
 *                   data[<model>][ids], and it decides whose selection is
 *                   cleared and which tab count moves afterwards
 *   $ids    int[]   the rows being deleted
 *
 * Optional params:
 *   $inUrl  bool    the id already travels in the form's action (the
 *                   single-row delete() endpoints), so $ids is not posted
 *   $hard   bool    the deletion can only be permanent (the rows are already
 *                   soft-deleted), so no switch is offered — say so in the
 *                   confirmation's own `warning`
 */

$uid = 'del-' . dechex(mt_rand());
$hard = !empty($hard);
$accent = $this->ModalAccent->get('danger');

$payload = [
    'model' => $model,
    'ids' => array_values(array_map('intval', $ids)),
    'inUrl' => !empty($inUrl),
    'hard' => $hard,
    'messages' => [
        'done' => __('Deleted.'),
        'fail' => __('Could not delete — please try again.'),
    ],
];
?>
<?php if (!$hard): ?>
<div class="border rounded-2 px-3 py-3">
    <div class="form-check form-switch mb-0">
        <input class="form-check-input" type="checkbox" role="switch"
               id="<?= h($uid) ?>-hard" data-delete-permanent>
        <label class="form-check-label fw-semibold d-flex align-items-center gap-2"
               for="<?= h($uid) ?>-hard" style="font-size:.85rem;">
            <i class="fas fa-trash-can <?= h($accent['textClass']) ?>"
               style="font-size:.75rem; <?= $accent['textStyle'] ?>"></i>
            <?= __('Delete permanently') ?>
        </label>
    </div>

    <div data-delete-note="soft">
        <?= $this->element('genericElementsBS5/Forms/field_hint', [
            'text' => __('Left off, it is soft-deleted: it stays in the event under Deleted and can be restored.'),
            'class' => 'mt-2',
        ]) ?>
    </div>
    <div data-delete-note="hard" class="d-none">
        <?= $this->element('genericElementsBS5/Forms/field_hint', [
            'text' => __('It is removed for good. This cannot be undone.'),
            'icon' => 'fas fa-triangle-exclamation mt-1 text-danger',
            'class' => 'mt-2',
        ]) ?>
    </div>
</div>
<?php endif; ?>
<script type="application/json" data-delete-mode><?= json_encode(
    $payload,
    JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT
) ?></script>
