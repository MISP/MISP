<?php
/*
 * The "also email the subscribers" switch of the event publish modal, off by
 * default — publishing is the action, notifying is the opt-in.
 *
 * It deliberately carries **no name attribute**: the switch is never posted.
 * MISP's SecurityComponent blackholes a POST carrying a field the rendered form
 * did not declare, and which of the two sibling forms gets submitted is decided
 * in JavaScript from `checked` (see Events/ajax/eventPublishConfirmationForm).
 *
 * Required params:
 *   $uid      string  unique prefix for the ids the modal's script binds to
 *
 * Optional params:
 *   $checked  bool    initial state (default false)
 *   $accent   string  accent key, see ModalAccent (default 'event')
 */

$uid = $uid ?? 'publish';
$checked = !empty($checked);
$accent = $this->ModalAccent->get($accent ?? 'event');
?>
<div class="border rounded-2 px-3 py-3">
    <div class="form-check form-switch mb-0">
        <input class="form-check-input" type="checkbox" role="switch"
               id="<?= h($uid) ?>-notify"<?= $checked ? ' checked' : '' ?>>
        <label class="form-check-label fw-semibold d-flex align-items-center gap-2"
               for="<?= h($uid) ?>-notify" style="font-size:.85rem;">
            <i class="fas fa-paper-plane <?= h($accent['textClass']) ?>"
               style="font-size:.75rem; <?= $accent['textStyle'] ?>"></i>
            <?= __('Send notification email') ?>
        </label>
    </div>

    <?= $this->element('genericElementsBS5/Forms/field_hint', [
        'text' => __('Emails the users who asked to be notified of new events. Leave it off for minor changes.'),
        'class' => 'mt-2',
    ]) ?>
</div>
