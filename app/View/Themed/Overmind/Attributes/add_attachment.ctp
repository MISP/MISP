<?php

$amber      = '#F59E0B';
$amberSoft  = 'rgba(245, 158, 11, .08)';
$amberLine  = 'rgba(245, 158, 11, .85)';

$eventId      = h($event['Event']['id'] ?? '');
$currentDist  = (int)$initialDistribution;

/* Object template option maps -------------------------------------------- */
$maliciousOptions = [];
foreach ($attachmentObjectTemplates['malicious'] as $tpl) {
    $maliciousOptions[$tpl['uuid']] = $tpl['label'];
}
$maliciousDefault = array_key_first($maliciousOptions);

$nonMaliciousOptions = [];
foreach ($attachmentObjectTemplates['non_malicious'] as $tpl) {
    $key = $tpl['uuid'] === null ? '' : $tpl['uuid'];
    $nonMaliciousOptions[$key] = $tpl['label'];
}
$nonMaliciousDefault = array_key_first($nonMaliciousOptions);

echo $this->Form->create('Attribute', [
    'novalidate' => true,
    'enctype'    => 'multipart/form-data',
    'onSubmit'   => 'document.getElementById("AttributeMalware").removeAttribute("disabled");',
]);
?>

<!-- ── MODAL HEADER ─────────────────────────────────────────── -->
<div class="px-4 pt-3 pb-3 d-flex align-items-center justify-content-between"
     style="background:<?= $amberSoft ?>;
            border-bottom:2px solid <?= $amberLine ?>;">
    <div>
        <div class="text-uppercase fw-semibold mb-1"
             style="font-size:.58rem; letter-spacing:.12em; opacity:.85;
                    color:<?= $amber ?>;">
            <?= __('Attachments') ?>
        </div>
        <h4 class="mb-0 fw-bold d-flex align-items-center gap-2">
            <i class="fas fa-paperclip"
               style="font-size:1.25rem; color:<?= $amber ?>;"></i>
            <?= __('Add Attachment(s)') ?>
        </h4>
    </div>
    <i class="fas fa-paperclip"
       style="font-size:2rem; opacity:.45; color:<?= $amber ?>;"></i>
</div>

<div class="container-fluid px-4 py-4">
    <div class="d-flex flex-column gap-4">

        <?= $this->Form->hidden('event_id', ['value' => $eventId]) ?>

        <!-- ── CATEGORY ────────────────────────────────────────── -->
        <div class="w-100">
            <div class="fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em; color:<?= $amber ?>;">
                <?= __('Category') ?>
                <span class="badge"
                      style="font-size:.55rem; opacity:.85; font-weight:700;
                             background:<?= $amber ?>; color:#fff;">
                    <?= __('REQUIRED') ?>
                </span>
            </div>
            <?= $this->Form->select('category', $categories, [
                'id'      => 'AttributeCategory',
                'class'   => 'form-select',
                'default' => 'Payload delivery',
                'empty'   => false,
            ]) ?>
        </div>


        <!-- ── FILES ───────────────────────────────────────────── -->
        <div class="w-100">
            <div class="fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em; color:<?= $amber ?>;">
                <?= __('Files') ?>
                <span class="badge"
                      style="font-size:.55rem; opacity:.85; font-weight:700;
                             background:<?= $amber ?>; color:#fff;">
                    <?= __('REQUIRED') ?>
                </span>
            </div>
            <div class="rounded-2 p-3"
                 style="background:<?= $amberSoft ?>;
                        border:1px dashed <?= $amberLine ?>;">
                <?= $this->Form->file('values.', [
                    'multiple' => true,
                    'id'       => 'AttributeValues',
                    'class'    => 'form-control',
                ]) ?>
                <div class="d-flex align-items-center gap-1 mt-2 text-muted"
                     style="font-size:.75rem;">
                    <i class="fas fa-circle-info" style="font-size:.65rem;"></i>
                    <?= __('Select one or more files to upload to this event.') ?>
                </div>
            </div>
        </div>


        <!-- ── COMMENT ─────────────────────────────────────────── -->
        <div class="w-100">
            <div class="fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em; color:<?= $amber ?>;">
                <?= __('Contextual Comment') ?>
            </div>
            <?= $this->Form->text('comment', [
                'id'          => 'AttributeComment',
                'class'       => 'w-100 border-0 bg-transparent py-1',
                'style'       => 'border-bottom:1px solid #d8dde3 !important;'
                    . ' outline:none; font-size:.925rem;',
                'placeholder' => __('Add a contextual comment…'),
            ]) ?>
        </div>


        <!-- ── DISTRIBUTION / SHARING GROUP ───────────────────── -->
        <div class="w-100">
            <div class="fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em; color:<?= $amber ?>;">
                <?= __('Distribution') ?>
            </div>
            <div class="d-flex gap-3">

                <div class="flex-fill">
                    <?= $this->Form->select('distribution', $distributionLevels, [
                        'id'    => 'AttributeDistribution',
                        'class' => 'form-select',
                        'value' => $currentDist,
                    ]) ?>
                </div>

                <div class="flex-fill"
                     id="SGContainer"
                     style="<?= $currentDist !== 4 ? 'display:none;' : '' ?>">
                    <?php if (!empty($sharingGroups)): ?>
                        <?= $this->Form->select('sharing_group_id', $sharingGroups, [
                            'id'    => 'AttributeSharingGroupId',
                            'empty' => __('Select a sharing group…'),
                            'class' => 'form-select',
                        ]) ?>
                    <?php endif; ?>
                </div>

            </div>
        </div>


        <!-- ── SETTINGS ────────────────────────────────────────── -->
        <div class="w-100">

            <div class="fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em; color:<?= $amber ?>;">
                <?= __('Settings') ?>
            </div>

            <div class="row g-2 mb-3">

                <div class="col-md-6">
                    <label id="card-malware"
                           class="d-flex align-items-center gap-3 rounded-2 p-3
                                  h-100 w-100 user-select-none mb-0"
                           style="cursor:pointer; border:1px solid #dee2e6;
                                  transition:border-color .15s, background .15s;">
                        <?= $this->Form->checkbox('malware', [
                            'id'      => 'AttributeMalware',
                            'checked' => true,
                            'class'   => 'form-check-input flex-shrink-0',
                            'style'   => 'margin-top:0;',
                        ]) ?>
                        <div class="flex-fill">
                            <div class="fw-bold text-uppercase"
                                 style="font-size:.72rem; letter-spacing:.06em; line-height:1.2;">
                                <?= __('Malware Sample') ?>
                            </div>
                            <div class="text-muted"
                                 style="font-size:.76rem; margin-top:.2rem; line-height:1.3;">
                                <?= __('Encrypt and hash the uploaded file(s)') ?>
                            </div>
                        </div>
                        <i id="icon-malware" class="fas fa-biohazard"
                           style="font-size:.95rem; color:#adb5bd; opacity:.7;
                                  transition:color .15s;"></i>
                    </label>
                </div>

                <div class="col-md-6" id="advanced_input" style="display:none;">
                    <label id="card-advanced"
                           class="d-flex align-items-center gap-3 rounded-2 p-3
                                  h-100 w-100 user-select-none mb-0"
                           style="cursor:pointer; border:1px solid #dee2e6;
                                  transition:border-color .15s;">
                        <?= $this->Form->checkbox('advanced', [
                            'id'                   => 'AttributeAdvanced',
                            'checked'              => false,
                            'disabled'             => !$advancedExtractionAvailable,
                            'data-disabled-reason' => !$advancedExtractionAvailable
                                ? __('Advanced extraction is not installed') : '',
                            'class'                => 'form-check-input flex-shrink-0',
                            'style'                => 'margin-top:0;',
                        ]) ?>
                        <div class="flex-fill">
                            <div class="fw-bold text-uppercase"
                                 style="font-size:.72rem; letter-spacing:.06em; line-height:1.2;">
                                <?= __('Advanced Extraction') ?>
                            </div>
                            <div class="text-muted"
                                 style="font-size:.76rem; margin-top:.2rem; line-height:1.3;">
                                <?= $advancedExtractionAvailable
                                    ? __('Extract embedded indicators from the sample')
                                    : __('Advanced extraction is not installed') ?>
                            </div>
                        </div>
                        <i class="fas fa-microscope"
                           style="font-size:.95rem; color:#adb5bd; opacity:.7;"></i>
                    </label>
                </div>

            </div>


            <!-- ── OBJECT TEMPLATE ─────────────────────────────── -->
            <div id="MaliciousObjectTemplateContainer">
                <div class="fw-bold text-uppercase mb-2"
                     style="font-size:.65rem; letter-spacing:.1em; color:<?= $amber ?>;">
                    <?= __('Object Template') ?>
                </div>
                <?= $this->Form->select('object_template_malicious', $maliciousOptions, [
                    'id'       => 'AttributeObjectTemplateMalicious',
                    'class'    => 'form-select',
                    'value'    => $maliciousDefault,
                    'empty'    => false,
                ]) ?>
            </div>

            <div id="NonMaliciousObjectTemplateContainer" style="display:none;">
                <div class="fw-bold text-uppercase mb-2"
                     style="font-size:.65rem; letter-spacing:.1em; color:<?= $amber ?>;">
                    <?= __('Object Template') ?>
                </div>
                <?= $this->Form->select('object_template_non_malicious', $nonMaliciousOptions, [
                    'id'       => 'AttributeObjectTemplateNonMalicious',
                    'class'    => 'form-select',
                    'value'    => $nonMaliciousDefault,
                    'empty'    => false,
                ]) ?>
            </div>

        </div>

    </div>


    <!-- ── FOOTER ─────────────────────────────────────────────── -->
    <div class="d-flex justify-content-between align-items-center mt-4 pt-3 flex-wrap gap-2">
        <div class="text-muted" style="font-size:.75rem;">
            <?= __('Event') ?>:
            <strong class="text-body">#<?= $eventId ?></strong>
        </div>
        <div class="d-flex gap-2">
            <a href="<?= h($baseurl . '/events/view/' . $eventId) ?>"
               class="btn btn-outline-secondary btn-sm"
               data-bs-dismiss="modal">
                <i class="fas fa-times me-1"></i><?= __('Discard') ?>
            </a>
            <?= $this->Form->button(
                '<i class="fas fa-upload me-1"></i> ' . __('Upload'),
                [
                    'class'       => 'btn btn-sm text-white',
                    'style'       => 'background:' . $amber . '; border-color:' . $amber . ';',
                    'escapeTitle' => false,
                ]
            ) ?>
        </div>
    </div>

</div>

<?= $this->Form->end() ?>

<?php if (!$ajax): ?>
    <?= $this->element('/genericElements/SideMenu/side_menu', [
        'menuList' => 'event',
        'menuItem' => 'addAttachment',
        'event'    => $event,
    ]) ?>
<?php endif; ?>

<script>
var formZipTypeValues = <?= json_encode($isMalwareSampleCategory) ?>;
var fileTemplateUuid  = <?= json_encode($maliciousDefault) ?>;

(function () {
    var AMBER      = '#F59E0B';
    var AMBER_SOFT = 'rgba(245, 158, 11, .08)';
    var AMBER_LINE = 'rgba(245, 158, 11, .85)';

    function init() {
        var malwareCb = document.getElementById('AttributeMalware');
        var distEl    = document.getElementById('AttributeDistribution');
        var catEl     = document.getElementById('AttributeCategory');
        var tplMalEl  = document.getElementById('AttributeObjectTemplateMalicious');

        /* Show/hide the sharing-group select */
        function toggleSg(val) {
            var sg = document.getElementById('SGContainer');
            if (sg) { sg.style.display = parseInt(val, 10) === 4 ? '' : 'none'; }
        }

        /* Malware-sample card: amber only while checked, neutral grey otherwise */
        function applyMalwareCard() {
            var card = document.getElementById('card-malware');
            var icon = document.getElementById('icon-malware');
            if (!malwareCb || !card) { return; }
            if (malwareCb.checked) {
                card.style.borderColor = AMBER_LINE;
                card.style.background  = AMBER_SOFT;
                if (icon) { icon.style.color = AMBER; icon.style.opacity = '1'; }
            } else {
                card.style.borderColor = '#dee2e6';
                card.style.background  = '';
                if (icon) { icon.style.color = '#adb5bd'; icon.style.opacity = '.7'; }
            }
        }

        function updateAdvancedVisibility() {
            var adv = document.getElementById('advanced_input');
            if (!adv) { return; }
            var isFileTemplate = tplMalEl && tplMalEl.value === fileTemplateUuid;
            adv.style.display =
                (malwareCb && malwareCb.checked && isFileTemplate) ? '' : 'none';
        }

        function onMalwareChange() {
            var mal     = document.getElementById('MaliciousObjectTemplateContainer');
            var non     = document.getElementById('NonMaliciousObjectTemplateContainer');
            var checked = malwareCb && malwareCb.checked;
            if (mal) { mal.style.display = checked ? '' : 'none'; }
            if (non) { non.style.display = checked ? 'none' : ''; }
            applyMalwareCard();
            updateAdvancedVisibility();
        }

        /* Distribution: icon + colour badge in the dedicated input
           (shared helper from mispOvermind.js) */
        if (typeof initDistributionSelect === 'function') {
            initDistributionSelect('AttributeDistribution', toggleSg);
        }
        /* Category, sharing group and object templates: plain TomSelect,
           initialised by id so we never touch elements outside this form. */
        if (typeof TomSelect !== 'undefined') {
            [
                'AttributeCategory',
                'AttributeSharingGroupId',
                'AttributeObjectTemplateMalicious',
                'AttributeObjectTemplateNonMalicious'
            ].forEach(function (id) {
                var el = document.getElementById(id);
                if (el && !el.tomselect) {
                    new TomSelect(el, { create: false, persist: false });
                }
            });
        }

        /* Category drives the malware checkbox + object-template panels.
           TomSelect dispatches a native change on the underlying select. */
        if (catEl) {
            catEl.addEventListener('change', function () {
                if (malwareCb && formZipTypeValues) {
                    malwareCb.checked = !!formZipTypeValues[catEl.value];
                }
                onMalwareChange();
            });
        }

        if (tplMalEl) {
            tplMalEl.addEventListener('change', updateAdvancedVisibility);
        }

        if (malwareCb) {
            malwareCb.addEventListener('change', onMalwareChange);
        }

        /* Initial state */
        toggleSg(distEl ? distEl.value : 0);
        onMalwareChange();
    }

    if (document.readyState !== 'loading') {
        init();
    } else {
        document.addEventListener('DOMContentLoaded', init);
    }
})();
</script>
