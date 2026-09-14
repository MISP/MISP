<?php
$action = $this->request->params['action'];
$isEdit = $action === 'edit';

App::uses('EventTemplateDependencies', 'Tools');

$offerTemplateAlternative = false;
if (!$isEdit
    && !EventTemplateDependencies::missing()
    && $this->Acl->canAccess('eventTemplates', 'instantiate')
) {
    App::uses('ClassRegistry', 'Utility');
    $__et = ClassRegistry::init('EventTemplate');
    $__conds = ['EventTemplate.active' => 1];
    if (empty($isSiteAdmin)) {
        $__conds['OR'] = [
            'EventTemplate.org_id' => (int)$me['org_id'],
            'EventTemplate.distribution' => 1,
        ];
    }
    $offerTemplateAlternative = (bool)$__et->find('count', [
        'recursive' => -1,
        'conditions' => $__conds,
    ]);
}

$currentDistribution = isset($event['Event']['distribution'])
    ? (int)$event['Event']['distribution']
    : (int)$initialDistribution;

$currentThreatLevel = isset($event['Event']['threat_level_id'])
    ? (int)$event['Event']['threat_level_id']
    : (int)(Configure::check('MISP.default_event_threat_level')
        ? Configure::read('MISP.default_event_threat_level')
        : 3);

$currentAnalysis = isset($event['Event']['analysis'])
    ? (int)$event['Event']['analysis']
    : 0;

$currentDate = !empty($event['Event']['date'])
    ? $event['Event']['date']
    : date('Y-m-d');

$analystName = !empty($me['email']) ? $me['email'] : '';
$orgName     = !empty($me['Organisation']['name'])
    ? $me['Organisation']['name']
    : '';

echo $this->Form->create('Event', ['id' => 'EventForm', 'novalidate' => true]);
?>

<?= $this->element('genericElementsBS5/Forms/modal_header', [
    'accent' => 'event',
    'eyebrow' => __('Events'),
    'title' => $isEdit ? __('Edit Event') : __('Add Event'),
    'description' => $isEdit ? '' : __('The event created will be visible to the organisations having an account on this platform, but not synchronised to other MISP instances until it is published.'),
    'icon' => 'misp-icon misp-icon-event misp-simple',
    'isEdit' => $isEdit,
]) ?>

<div class="container-fluid px-4 py-4">

    <div class="d-flex flex-column gap-4 px-2">

        <?php if ($offerTemplateAlternative): ?>
            <div class="alert alert-light border d-flex align-items-center gap-3 mb-0"
                 role="alert" style="border-color:var(--primary) !important;">
                <div class="flex-grow-1">
                    <div class="fw-semibold" style="font-size:.85rem;">
                        <?= h(__('Have a template for this report?')) ?>
                    </div>
                    <div class="text-muted" style="font-size:.75rem; margin-top:.15rem;">
                        <?= h(__('Skip the manual creation and pick a guided event-template walkthrough.')) ?>
                    </div>
                </div>
                <button type="button"
                        class="btn btn-primary btn-sm flex-shrink-0 text-nowrap"
                        onclick="event.preventDefault(); openEventTemplatePicker();">
                    <i class="fas fa-bolt me-1"></i>
                    <?= h(__('Use a template')) ?>
                </button>
            </div>
        <?php endif; ?>

        <!-- ── EVENT INFO (+ EXTENDS, ITS SUB-FIELD) ─────────── -->
        <div class="w-100">
            <div class="ov-form-group">
                <?= $this->element('genericElementsBS5/Forms/section_label', [
                    'accent' => 'primary',
                    'label' => __('Event Info'),
                    'required' => true,
                    'for' => 'EventInfo',
                ]) ?>
                <?= $this->Form->textarea('info', [
                    'class'             => 'ov-form-line fs-5',
                    'rows'              => 2,
                    'placeholder'       => __('Describe the threat event in precise terms…'),
                    'id'                => 'EventInfo',
                    'data-required-msg' => __('Please provide a name for the event.'),
                ]) ?>
            </div>

            <div class="ov-subfield ms-2">
                <div class="ov-subfield-row">
                    <label class="ov-subfield-label" for="EventExtendsUuid"
                           title="<?= h(__('If this event references another event, enter its ID or UUID here.')) ?>">
                        <i class="fas fa-code-branch"></i>
                        <?= __('Extends') ?>
                    </label>
                    <div class="ov-form-box ov-subfield-box">
                        <?= $this->Form->text('extends_uuid', [
                            'class'       => 'ov-form-bare',
                            'id'          => 'EventExtendsUuid',
                            'placeholder' => __('ID or UUID of the event this one extends'),
                        ]) ?>
                    </div>
                </div>
                <div id="event_preview" class="mt-2 d-none"></div>
            </div>
        </div>


        <!-- ── DISTRIBUTION / SHARING GROUP ───────────────────── -->
        <div class="w-100" data-tour="event-distribution">
            <?= $this->element('genericElementsBS5/Forms/distribution_field', [
                'value' => $currentDistribution,
                'id' => 'distribution-select',
                'sgEmpty' => __('Select a sharing group…'),
            ]) ?>
        </div>


        <!-- ── ANALYSIS + THREAT ───────────────────────────────
             Side by side  and each one a slider -->
        <div class="row g-4 w-100 mx-0">

        <div class="col-md-6 ps-0" data-tour="event-analysis">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'primary',
                'label' => __('Analysis Level'),
            ]) ?>
            <?php
            $analysisMeta = [
                0 => ['tone' => '#0d6efd', 'sub' => __('Raw intelligence')],
                1 => ['tone' => '#fd7e14', 'sub' => __('Under investigation')],
                2 => ['tone' => '#198754', 'sub' => __('Verified & closed')],
            ];
            $analysisOptions = [];
            foreach ($analysisLevels as $analysisId => $analysisName) {
                $analysisOptions[] = ($analysisMeta[$analysisId] ?? [
                    'tone' => '#6c757d',
                ]) + ['value' => $analysisId, 'title' => $analysisName];
            }
            ?>
            <?= $this->element('genericElementsBS5/Forms/choice_slider', [
                'field' => 'analysis',
                'id' => 'EventAnalysisInput',
                'value' => $currentAnalysis,
                'ariaLabel' => __('Analysis level'),
                'options' => $analysisOptions,
            ]) ?>
        </div>



        <div class="col-md-6" data-tour="event-threat">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'primary',
                'label' => __('Threat Level'),
            ]) ?>
            <?php
            $threatMeta = [
                4 => ['tone' => '#41464b', 'sub' => __('No risk')],
                3 => ['tone' => '#ffc107', 'sub' => __('Opportunistic')],
                2 => ['tone' => '#fd7e14', 'sub' => __('Targeted campaign')],
                1 => ['tone' => '#dc3545', 'sub' => __('Active exploitation')],
            ];
            $threatOptions = [];
            foreach ($threatMeta as $threatId => $meta) {
                if (isset($threatLevels[$threatId])) {
                    $threatOptions[] = $meta + [
                        'value' => $threatId,
                        'title' => $threatLevels[$threatId],
                    ];
                }
            }
            foreach ($threatLevels as $threatId => $threatName) {
                if (!isset($threatMeta[$threatId])) {
                    $threatOptions[] = [
                        'value' => $threatId,
                        'title' => $threatName,
                        'tone' => '#6c757d',
                    ];
                }
            }
            ?>
            <?= $this->element('genericElementsBS5/Forms/choice_slider', [
                'field' => 'threat_level_id',
                'id' => 'EventThreatLevelInput',
                'value' => $currentThreatLevel,
                'ariaLabel' => __('Threat level'),
                'options' => $threatOptions,
            ]) ?>
        </div>

        </div><!-- /row: analysis + threat -->

        <!-- ── DATE ───────────────────────────────────────────── -->
        <div class="w-100 ov-form-group" data-tour="event-date">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'primary',
                'label' => __('Event Date (UTC)'),
                'required' => true,
                'for' => 'EventDateDisplay',
            ]) ?>
            <div class="ov-form-box">
                <input type="text"
                       id="EventDateDisplay"
                       class="ov-form-bare"
                       inputmode="numeric"
                       autocomplete="off"
                       placeholder="DD/MM/YYYY"
                       data-invalid-msg="<?= h(__('Enter the event date as DD/MM/YYYY.')) ?>"
                       value="<?= h(date('d/m/Y', strtotime($currentDate))) ?>">
                <?= $this->Form->hidden('date', [
                    'id'    => 'EventDate',
                    'value' => $currentDate,
                ]) ?>
            </div>
        </div>

    </div>

    <?php
    $footerMeta = [];
    if ($analystName) {
        $footerMeta[] = ['label' => __('Analyst'), 'value' => $analystName];
        if ($orgName) {
            $footerMeta[] = ['label' => __('Org'), 'value' => $orgName];
        }
    }
    echo $this->element('genericElementsBS5/Forms/modal_footer', [
        'isEdit' => $isEdit,
        'meta' => $footerMeta,
        'submit' => [
            'label' => $isEdit ? __('Save Changes') : __('Create Event Entry'),
            'icon' => 'fas fa-circle-plus',
            'id' => 'EventSubmitButton',
            'class' => 'btn-primary',
        ],
    ]);
    ?>

</div>

<?= $this->Form->end() ?>

<?php if ($offerTemplateAlternative): ?>
    <?= $this->element('eventTemplates/templatePickerModal') ?>
<?php endif; ?>

<script>
/* A modal body runs its scripts after the document is ready; a full page load
 * gets here first. initEventForm() is a no-op the second time either way. */
(function () {
    var start = function () { initEventForm(document.getElementById('EventForm')); };
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', start);
    } else {
        start();
    }
})();
</script>