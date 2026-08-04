<?php
/**
 * Proposal modal.
 *
 * Served by ShadowAttributesController::edit($attributeId) (GET) and posted
 * back to the same action.
 * The edit action returns JSON for Overmind AJAX submits.
 */
$saData      = $this->request->data['ShadowAttribute'] ?? [];
$attrId      = $attribute_id;
$eventId     = $event['Event']['id'] ?? '';
$currentCat  = $saData['category'] ?? '';
$currentType = $saData['type']     ?? '';
$toIdsChecked = !empty($saData['to_ids']);


$this->Form->unlockField('ShadowAttribute.proposal_to_delete');

echo $this->Form->create('ShadowAttribute', [
    'url' => ['controller' => 'shadow_attributes', 'action' => 'edit', $attrId],
    'id'  => 'proposalForm',
    'novalidate' => true,
]);
?>

<!-- ── MODAL HEADER ─────────────────────────────────────────── -->
<div class="px-4 pt-3 pb-3 d-flex align-items-center justify-content-between"
     style="background:#97CC040f; border-bottom:2px solid var(--attribute);">
    <div>
        <div class="text-attribute text-uppercase fw-semibold mb-1"
             style="font-size:.58rem; letter-spacing:.12em; opacity:.85;">
            <?= __('Proposal') ?>
        </div>
        <h4 class="mb-0 fw-bold d-flex align-items-center gap-2">
            <i class="fas fa-comment-dots text-attribute" style="font-size:1.25rem;"></i>
            <?= __('Propose a change') ?>
        </h4>
    </div>
    <span class="misp-icon misp-icon-attribute misp-simple text-attribute" style="font-size:2rem; opacity:.5;"></span>
</div>

<div class="container-fluid px-4 py-4">
    <div class="d-flex flex-column gap-4">

        <!-- ── DELETION TOGGLE ──────────────────────────────────── -->
        <label id="proposeDeleteCard"
               class="d-flex align-items-center gap-3 rounded-2 p-3 user-select-none mb-0"
               style="cursor:pointer; border:1px solid #dee2e6;">
            <input type="checkbox" id="proposeDeleteToggle"
                   class="form-check-input flex-shrink-0" style="margin-top:0;">
            <div class="flex-fill">
                <div class="fw-bold text-uppercase"
                     style="font-size:.72rem; letter-spacing:.06em; line-height:1.2;">
                    <?= __('Propose deletion of this attribute') ?>
                </div>
                <div class="text-muted" style="font-size:.76rem; margin-top:.2rem; line-height:1.3;">
                    <?= __('Submit a proposal to remove this attribute instead of editing it.') ?>
                </div>
            </div>
            <i id="proposeDeleteIcon" class="fas fa-trash"
               style="font-size:.95rem; color:#adb5bd; opacity:.7; transition:color .15s;"></i>
        </label>

        <!-- ── EDIT FIELDS (greyed when proposing deletion) ─────── -->
        <fieldset id="proposalEditFields" class="border-0 p-0 m-0 d-flex flex-column gap-4">

            <div class="row g-3">
                <div class="col-md-6">
                    <div class="text-attribute fw-bold text-uppercase mb-2"
                         style="font-size:.65rem; letter-spacing:.1em;">
                        <?= __('Category') ?>
                    </div>
                    <?= $this->Form->select('category', $categories, [
                        'id'    => 'ShadowAttributeCategory',
                        'class' => 'form-select',
                        'value' => $currentCat,
                        'empty' => __('(choose one)'),
                    ]) ?>
                </div>
                <div class="col-md-6">
                    <div class="text-attribute fw-bold text-uppercase mb-2"
                         style="font-size:.65rem; letter-spacing:.1em;">
                        <?= __('Type') ?>
                    </div>
                    <?= $this->Form->select('type', $types, [
                        'id'    => 'ShadowAttributeType',
                        'class' => 'form-select',
                        'value' => $currentType,
                        'empty' => __('(choose one)'),
                    ]) ?>
                </div>
            </div>

            <div class="w-100">
                <div class="text-attribute fw-bold text-uppercase mb-2"
                     style="font-size:.65rem; letter-spacing:.1em;">
                    <?= __('Value') ?>
                </div>
                <?= $this->Form->textarea('value', [
                    'id'    => 'ShadowAttributeValue',
                    'class' => 'w-100 rounded-2 p-3',
                    'style' => 'background:var(--bs-tertiary-bg, #f8f9fa);'
                        . ' border:1px solid #d8dde3; resize:vertical; outline:none;'
                        . ' font-size:.9rem; min-height:88px; color:inherit; font-family:inherit;',
                    'rows'  => 4,
                ]) ?>
            </div>

            <div class="w-100">
                <div class="text-attribute fw-bold text-uppercase mb-2"
                     style="font-size:.65rem; letter-spacing:.1em;">
                    <?= __('Contextual Comment') ?>
                </div>
                <?= $this->Form->text('comment', [
                    'id'    => 'ShadowAttributeComment',
                    'class' => 'w-100 border-0 bg-transparent py-1',
                    'style' => 'border-bottom:1px solid #d8dde3 !important; outline:none; font-size:.925rem;',
                    'placeholder' => __('Add a contextual comment…'),
                ]) ?>
            </div>

            <label id="proposalIdsCard"
                   class="d-flex align-items-center gap-3 rounded-2 p-3 user-select-none mb-0"
                   style="cursor:pointer; border:1px solid <?= $toIdsChecked ? '#ffc107' : '#dee2e6' ?>; transition:border-color .15s;">
                <?= $this->Form->checkbox('to_ids', [
                    'id'    => 'ShadowAttributeToIds',
                    'class' => 'form-check-input flex-shrink-0',
                    'style' => 'margin-top:0;',
                    'checked' => $toIdsChecked,
                ]) ?>
                <div class="flex-fill">
                    <div class="fw-bold text-uppercase"
                         style="font-size:.72rem; letter-spacing:.06em; line-height:1.2;">
                        <?= __('For IDS') ?>
                    </div>
                    <div class="text-muted" style="font-size:.76rem; margin-top:.2rem; line-height:1.3;">
                        <?= __('Send to Intrusion Detection System') ?>
                    </div>
                </div>
                <i id="proposalIdsIcon" class="fas fa-shield-halved"
                   style="font-size:.95rem; color:<?= $toIdsChecked ? '#ffc107' : '#adb5bd' ?>; transition:color .15s;"></i>
            </label>

        </fieldset>

        <?= $this->Form->hidden('proposal_to_delete', [
            'id'    => 'ProposalToDelete',
            'value' => 0,
        ]) ?>
    </div>

    <!-- ── FOOTER ─────────────────────────────────────────────── -->
    <div class="d-flex justify-content-between align-items-center mt-4 pt-3 flex-wrap gap-2">
        <div class="text-muted" style="font-size:.75rem;">
            <?= __('Event') ?>:
            <strong class="text-body">#<?= h($eventId) ?></strong>
            &middot; <?= __('Attribute') ?>:
            <strong class="text-body">#<?= h($attrId) ?></strong>
        </div>
        <div class="d-flex gap-2">
            <button type="button" class="btn btn-outline-secondary btn-sm" data-bs-dismiss="modal">
                <i class="fas fa-times me-1"></i><?= __('Cancel') ?>
            </button>
            <button type="submit" id="proposalSubmitBtn" class="btn btn-attribute btn-sm text-white">
                <i class="fas fa-comment-dots me-1"></i><span id="proposalSubmitLabel"><?= __('Submit proposal') ?></span>
            </button>
        </div>
    </div>

</div>

<?= $this->Form->end() ?>

<script>
(function () {
    var form        = document.getElementById('proposalForm');
    if (!form) { return; }
    var toggle      = document.getElementById('proposeDeleteToggle');
    var deleteFlag  = document.getElementById('ProposalToDelete');
    var fields      = document.getElementById('proposalEditFields');
    var card        = document.getElementById('proposeDeleteCard');
    var icon        = document.getElementById('proposeDeleteIcon');
    var submitLabel = document.getElementById('proposalSubmitLabel');
    var msgFail     = <?= json_encode(__('Could not submit the proposal.')) ?>;
    var lblEdit     = <?= json_encode(__('Submit proposal')) ?>;
    var lblDelete   = <?= json_encode(__('Submit deletion proposal')) ?>;

    function syncDeletion() {
        var on = toggle.checked;
        deleteFlag.value = on ? 1 : 0;
        // Grey out via CSS only — never `disabled`, or the fields would be dropped from the POST and break the form-tampering token.
        if (fields) {
            fields.style.opacity = on ? '0.45' : '';
            fields.style.pointerEvents = on ? 'none' : '';
        }
        if (card) { card.style.borderColor = on ? '#dc3545' : '#dee2e6'; }
        if (icon) { icon.style.color = on ? '#dc3545' : '#adb5bd'; icon.style.opacity = on ? '1' : '.7'; }
        if (submitLabel) { submitLabel.textContent = on ? lblDelete : lblEdit; }
    }

    toggle.addEventListener('change', syncDeletion);
    syncDeletion();

    // IDS checkbox card colours
    var idsCheckbox = document.getElementById('ShadowAttributeToIds');
    var idsCard     = document.getElementById('proposalIdsCard');
    var idsIcon     = document.getElementById('proposalIdsIcon');
    function syncIds() {
        if (!idsCheckbox) { return; }
        var on = idsCheckbox.checked;
        if (idsCard) { idsCard.style.borderColor = on ? '#ffc107' : '#dee2e6'; }
        if (idsIcon) { idsIcon.style.color = on ? '#ffc107' : '#adb5bd'; }
    }
    if (idsCheckbox) { idsCheckbox.addEventListener('change', syncIds); syncIds(); }
}());
</script>
