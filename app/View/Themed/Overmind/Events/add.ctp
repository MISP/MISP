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

echo $this->Form->create('Event', ['novalidate' => true]);
?>

<!-- ── MODAL HEADER ─────────────────────────────────────────── -->
<div class="px-4 pt-3 pb-3 d-flex align-items-center justify-content-between"
     style="background:rgba(24,146,177,.06);
            border-bottom:2px solid var(--primary);">
    <div>
        <div class="text-uppercase fw-semibold mb-1 text-event"
             style="font-size:.58rem; letter-spacing:.12em; opacity:.85;">
            <?= __('Events') ?>
        </div>
        <h4 class="mb-0 fw-bold d-flex align-items-center gap-2">
            <i class="fas fa-<?= $isEdit ? 'pen-to-square' : 'circle-plus' ?> text-event"
               style="font-size:1.25rem;"></i>
            <?= $isEdit ? __('Edit Event') : __('Add Event') ?>
        </h4>
        <p class="text-muted mb-0" style="font-size:.75rem;">
            <?= !$isEdit
                ? __('The event created will be visible to the organisations having an account on this platform, but not synchronised to other MISP instances until it is published.')
                : __('') ?>
        </p>
    </div>
    <span class="misp-icon misp-icon-event misp-simple text-event" style="font-size:2rem; opacity:.5;"></span>
</div>

<div class="container-fluid px-4 py-4">

    <div class="d-flex flex-column gap-4">

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

        <!-- ── EVENT INFO ──────────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="d-flex align-items-center gap-2 text-primary fw-bold
                        text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Event Info') ?>
                <span class="badge bg-primary"
                      style="font-size:.55rem; opacity:.8; font-weight:700;">
                    <?= __('REQUIRED') ?>
                </span>
            </div>
            <?= $this->Form->textarea('info', [
                'class'             => 'w-100 border-0 bg-transparent fs-5 py-1',
                'style'             => 'border-bottom:1px solid #d8dde3 !important;'
                    . ' resize:none; outline:none;',
                'rows'              => 2,
                'placeholder'       => __('Describe the threat event in precise terms…'),
                'id'                => 'EventInfo',
                'data-required-msg' => __('Please provide a name for the event.'),
            ]) ?>
        </div>

        <!-- ── EXTENDS UUID ────────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="text-primary fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Extends Event') ?>
            </div>
            <div class="border rounded px-2 py-2"
                 style="border-color:#d8dde3;">
                <?= $this->Form->control('extends_uuid', [
                    'class'       => 'w-100 border-0 bg-transparent p-0',
                    'style'       => 'outline:none; font-size:.925rem;',
                    'id'          => 'EventExtendsUuid',
                    'placeholder' => 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX',
                ]) ?>
            </div>
            <div class="d-flex align-items-center gap-1 mt-1 text-muted"
                 style="font-size:.75rem;">
                <i class="fas fa-circle-info" style="font-size:.65rem;"></i>
                <?= __('If this event references another event, enter its ID or UUID here.') ?>
            </div>
            <div id="event_preview" class="mt-2" style="display:none;"></div>
        </div>


        <!-- ── DISTRIBUTION / SHARING GROUP ───────────────────── -->
        <div class="w-100 px-2">
            <div class="text-primary fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Distribution / Sharing Group') ?>
            </div>
            <div class="d-flex gap-3">

                <div class="flex-fill">
                    <?= $this->Form->select('distribution', $distributionLevels, [
                        'class' => 'form-select',
                        'id'    => 'distribution-select',
                        'value' => $currentDistribution,
                    ]) ?>
                </div>

                <div class="flex-fill<?= $currentDistribution === 4 ? '' : ' d-none' ?>"
                     id="sg-container">
                    <?= $this->Form->select('sharing_group_id', $sharingGroups, [
                        'empty' => __('Select a sharing group…'),
                        'class' => 'form-select tom-select',
                    ]) ?>
                </div>

            </div>
        </div>


        <!-- ── ANALYSIS LEVEL ──────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="text-primary fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Analysis Level') ?>
            </div>
            <?= $this->Form->select('analysis', $analysisLevels, [
                'id'    => 'EventAnalysisInput',
                'value' => $currentAnalysis,
                'style' => 'display:none',
            ]) ?>
            <div class="row g-2">

                <?php
                $analysisCards = [
                    ['value' => 0, 'dot' => '#0d6efd',
                     'title' => __('Initial'),  'sub' => __('Raw Intelligence')],
                    ['value' => 1, 'dot' => '#fd7e14',
                     'title' => __('Ongoing'),  'sub' => __('Under Investigation')],
                    ['value' => 2, 'dot' => '#198754',
                     'title' => __('Complete'), 'sub' => __('Verified &amp; Closed')],
                ];
                foreach ($analysisCards as $card):
                    $checked   = $currentAnalysis === $card['value'];
                    $cardStyle = $checked
                        ? 'border-color:var(--primary) !important;'
                            . ' background:rgba(24,146,177,.08);'
                        : 'border-color:#d8dde3;';
                ?>
                <div class="col event-card"
                     style="cursor:pointer;"
                     data-group="analysis"
                     data-value="<?= $card['value'] ?>">
                    <div class="border rounded p-2 d-flex flex-column gap-1 h-100"
                         style="transition:border-color .15s, background .15s;
                                <?= $cardStyle ?>">
                        <span class="rounded-circle d-inline-block mb-1"
                              style="width:.55rem; height:.55rem;
                                     background:<?= $card['dot'] ?>;"></span>
                        <span class="fw-bold" style="font-size:.875rem; line-height:1.2;">
                            <?= $card['title'] ?>
                        </span>
                        <span class="text-muted" style="font-size:.7rem; line-height:1.2;">
                            <?= $card['sub'] ?>
                        </span>
                    </div>
                </div>
                <?php endforeach; ?>

            </div>
        </div>



        <!-- ── THREAT LEVEL ────────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="text-primary fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Threat Level') ?>
            </div>
            <?= $this->Form->select('threat_level_id', $threatLevels, [
                'id'    => 'EventThreatLevelInput',
                'value' => $currentThreatLevel,
                'style' => 'display:none',
            ]) ?>
            <div class="row g-2">

                <?php
                $threatCards = [
                    ['value' => 3, 'dot' => '#ffc107',
                     'title' => __('Low'),    'sub' => __('Opportunistic')],
                    ['value' => 2, 'dot' => '#fd7e14',
                     'title' => __('Medium'), 'sub' => __('Targeted Campaign')],
                    ['value' => 1, 'dot' => '#dc3545',
                     'title' => __('High'),   'sub' => __('Active Exploitation')],
                ];
                foreach ($threatCards as $card):
                    $checked   = $currentThreatLevel === $card['value'];
                    $cardStyle = $checked
                        ? 'border-color:var(--primary) !important;'
                            . ' background:rgba(24,146,177,.08);'
                        : 'border-color:#d8dde3;';
                ?>
                <div class="col event-card"
                     style="cursor:pointer;"
                     data-group="threat"
                     data-value="<?= $card['value'] ?>">
                    <div class="border rounded p-2 d-flex flex-column gap-1 h-100"
                         style="transition:border-color .15s, background .15s;
                                <?= $cardStyle ?>">
                        <span class="rounded-circle d-inline-block mb-1"
                              style="width:.55rem; height:.55rem;
                                     background:<?= $card['dot'] ?>;"></span>
                        <span class="fw-bold" style="font-size:.875rem; line-height:1.2;">
                            <?= $card['title'] ?>
                        </span>
                        <span class="text-muted" style="font-size:.7rem; line-height:1.2;">
                            <?= $card['sub'] ?>
                        </span>
                    </div>
                </div>
                <?php endforeach; ?>

            </div>
        </div>

        <!-- ── DATE ───────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="text-primary fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Event Date (UTC)') ?>
            </div>
            <div class="border rounded px-2 py-2"
                 style="border-color:#d8dde3;">
                <input type="text"
                       id="EventDateDisplay"
                       class="w-100 border-0 bg-transparent p-0"
                       style="outline:none; font-size:.925rem;"
                       placeholder="DD/MM/YYYY"
                       value="<?= h(date('d/m/Y', strtotime($currentDate))) ?>">
                <?= $this->Form->hidden('date', [
                    'id'    => 'EventDate',
                    'value' => $currentDate,
                ]) ?>
            </div>
        </div>

    </div>

    <!-- ── FOOTER ─────────────────────────────────────────────── -->
    <div class="d-flex justify-content-between align-items-center
                mt-4 pt-3 flex-wrap gap-2">
        <div class="text-muted" style="font-size:.75rem;">
            <?php if ($analystName): ?>
                <?= __('Analyst') ?>: <strong class="text-body"><?= h($analystName) ?></strong>
                <?php if ($orgName): ?>
                    &nbsp;|&nbsp; <?= __('Org') ?>:
                    <strong class="text-body"><?= h($orgName) ?></strong>
                <?php endif; ?>
            <?php endif; ?>
        </div>
        <div class="d-flex gap-2">
            <button type="button" class="btn btn-outline-secondary btn-sm"
                    data-bs-dismiss="modal">
                <i class="fas fa-times me-1"></i><?= __('Discard') ?>
            </button>
            <?= $this->Form->button(
                '<i class="fas fa-circle-plus me-1"></i> '
                    . ($isEdit ? __('Save Changes') : __('Create Event Entry')),
                [
                    'class'       => 'btn btn-primary btn-sm',
                    'escapeTitle' => false,
                ]
            ) ?>
        </div>
    </div>

</div>

<?= $this->Form->end() ?>

<?php if ($offerTemplateAlternative): ?>
    <?= $this->element('eventTemplates/templatePickerModal') ?>
<?php endif; ?>

<script>
var _base = <?= json_encode($baseurl,
    JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
if (document.readyState !== 'loading') {
    initEventForm(_base);
} else {
    document.addEventListener('DOMContentLoaded', function () {
        initEventForm(_base);
    });
}
</script>