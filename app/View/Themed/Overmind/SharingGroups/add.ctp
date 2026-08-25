<?php
$edit = $this->request->params['action'] === 'edit' ? true : false;

if ($edit) {
    $canModifyUuid = false;
}

echo $this->Form->create('SharingGroup', [
    'class' => 'needs-validation',
    'id' => 'sharingGroupForm',
    'novalidate' => true
]);
?>

<!-- ── MODAL HEADER ─────────────────────────────────────────── -->
<div class="px-4 pt-3 pb-3 d-flex align-items-center justify-content-between"
     style="background:rgba(24,146,177,.06);
            border-bottom:2px solid var(--primary);">
    <div>
        <div class="text-primary text-uppercase fw-semibold mb-1"
             style="font-size:.58rem; letter-spacing:.12em; opacity:.85;">
            <?= __('Sharing Groups') ?>
        </div>
        <h4 class="mb-0 fw-bold d-flex align-items-center gap-2">
            <i class="fas fa-<?= $edit ? 'pen-to-square' : 'circle-plus' ?> text-primary"
               style="font-size:1.25rem;"></i>
            <?= $edit ? __('Edit Sharing Group') : __('Add Sharing Group') ?>
        </h4>
        <p class="text-muted mb-0" style="font-size:.75rem;">
            <?= __('Complete each section below — use the accordions to navigate, or "Next" to proceed step by step.') ?>
        </p>
    </div>
    <span class="misp-icon misp-icon-sharing-group misp-simple text-primary"
          style="font-size:2rem; opacity:.5;"></span>
</div>

<div class="container-fluid px-4 py-4" id="sg-wizard">

                <div class="accordion" id="sgAccordion">
                    <!-- ===================== STEP 1 : GENERAL ===================== -->
                    <div class="accordion-item border mb-2 rounded shadow-sm">
                        <h2 class="accordion-header" id="sgHeading1">
                            <button class="accordion-button rounded"
                                    type="button"
                                    data-bs-toggle="collapse"
                                    data-bs-target="#sgCollapse1"
                                    aria-expanded="true"
                                    aria-controls="sgCollapse1">
                                <span class="badge bg-primary me-2">1</span>
                                <?= __('General') ?>
                            </button>
                        </h2>
                        <div id="sgCollapse1"
                            class="accordion-collapse collapse show"
                            aria-labelledby="sgHeading1"
                            data-bs-parent="#sgAccordion">
                            <div class="accordion-body">

                                <!-- UUID -->
                                <?php if ($canModifyUuid): ?>
                                <div class="mb-3">
                                    <?= $this->Form->label('SharingGroupUuid', __('UUID'), ['class' => 'form-label fw-semibold']) ?>
                                    <input type="text"
                                        class="form-control bg-light"
                                        id="SharingGroupUuid"
                                        placeholder="<?= __('If not provided, a random UUID will be generated') ?>">
                                </div>
                                <?php endif; ?>

                                <!-- NAME -->
                                <div class="mb-3">
                                    <?= $this->Form->label('SharingGroupName', __('Name'), ['class' => 'form-label fw-semibold']) ?>
                                    <input type="text"
                                        class="form-control bg-light"
                                        id="SharingGroupName"
                                        required
                                        placeholder="<?= __('e.g. Multinational sharing group') ?>">
                                    <div class="invalid-feedback"><?= __('Please provide a name for this sharing group.') ?></div>
                                </div>

                                <!-- TYPE -->
                                <div class="mb-3">
                                    <?= $this->Form->label('SharingGroupReleasability', __('Releasable to'), ['class' => 'form-label fw-semibold']) ?>
                                    <input type="text"
                                        class="form-control bg-light"
                                        id="SharingGroupReleasability"
                                        placeholder="<?= __('e.g. Community1, Organisation1, Organisation2') ?>">
                                </div>

                                <!-- DESCRIPTION -->
                                <div class="mb-3">
                                    <?= $this->Form->label('SharingGroupDescription', __('Description'), ['class' => 'form-label fw-semibold']) ?>
                                    <textarea class="form-control bg-light"
                                            id="SharingGroupDescription"
                                            rows="4"
                                            placeholder="<?= __('A description of the sharing group.') ?>"></textarea>
                                </div>

                                <!-- SELECTABLE/ACTIVE -->
                                <div class="mb-3 form-check">
                                    <input type="checkbox"
                                        class="form-check-input"
                                        id="SharingGroupActive"
                                        value="1"
                                        checked>
                                    <label class="form-check-label" for="SharingGroupActive">
                                        <?= __('Make the sharing group selectable (active)') ?>
                                    </label>
                                    <div class="form-text">
                                        <?= __('Active sharing groups can be selected when creating events. Groups received via synchronisation are inactive by default.') ?>
                                    </div>
                                </div>

                                <div class="d-flex justify-content-end mt-3">
                                    <button type="button" class="btn btn-primary sg-next" data-next="sgCollapse2">
                                        <?= __('Next') ?> <i class="fas fa-chevron-down ms-1"></i>
                                    </button>
                                </div>

                            </div>
                        </div>
                    </div>

                    <!-- ===================== STEP 2 : ORGANISATIONS ===================== -->
                    <div class="accordion-item border mb-2 rounded shadow-sm">
                        <h2 class="accordion-header" id="sgHeading2">
                            <button class="accordion-button collapsed rounded"
                                    type="button"
                                    data-bs-toggle="collapse"
                                    data-bs-target="#sgCollapse2"
                                    aria-expanded="false"
                                    aria-controls="sgCollapse2">
                                <span class="badge bg-primary me-2">2</span>
                                <?= __('Organisations') ?>
                            </button>
                        </h2>
                        <div id="sgCollapse2"
                            class="accordion-collapse collapse"
                            aria-labelledby="sgHeading2"
                            data-bs-parent="#sgAccordion">
                            <div class="accordion-body">

                                <!-- LOCAL ORGS -->
                                <div class="mb-3">
                                    <label class="form-label fw-semibold"><?= __('Add local organisation') ?></label>
                                    <?= $this->Form->select('sg_local_org', array_combine(
                                        array_column(array_column($localOrgs ?? [], 'Organisation'), 'id'),
                                        array_column(array_column($localOrgs ?? [], 'Organisation'), 'name')
                                    ), [
                                        'empty'            => true,
                                        'class'            => 'form-select tom-select bg-light',
                                        'id'               => 'sg-local-org-select',
                                        'data-placeholder' => __('Search local organisations…'),
                                    ]) ?>
                                </div>

                                <!-- EXTERNAL ORGS -->
                                <div class="mb-3">
                                    <label class="form-label fw-semibold"><?= __('Add external organisation') ?></label>
                                    <?= $this->Form->select('sg_ext_org', array_combine(
                                        array_column(array_column($externalOrgs ?? [], 'Organisation'), 'id'),
                                        array_column(array_column($externalOrgs ?? [], 'Organisation'), 'name')
                                    ), [
                                        'empty'            => true,
                                        'class'            => 'form-select tom-select bg-light',
                                        'id'               => 'sg-ext-org-select',
                                        'data-placeholder' => __('Search external organisations…'),
                                    ]) ?>
                                </div>

                                <!-- Organisations table -->
                                <div class="table-responsive">
                                    <table class="table table-sm table-hover align-middle">
                                        <thead class="table-light">
                                            <tr>
                                                <th><?= __('Type') ?></th>
                                                <th><?= __('Name') ?></th>
                                                <th><?= __('UUID') ?></th>
                                                <th><?= __('Can extend') ?></th>
                                                <th><?= __('Actions') ?></th>
                                            </tr>
                                        </thead>
                                        <tbody id="organisations_table_body"></tbody>
                                    </table>
                                </div>

                                <div class="d-flex justify-content-between mt-3">
                                    <button type="button" class="btn btn-outline-secondary sg-prev" data-prev="sgCollapse1">
                                        <i class="fas fa-chevron-up me-1"></i><?= __('Previous') ?>
                                    </button>
                                    <button type="button" class="btn btn-primary sg-next" data-next="sgCollapse3">
                                        <?= __('Next') ?> <i class="fas fa-chevron-down ms-1"></i>
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- ===================== STEP 3 : MISP INSTANCES ===================== -->
                    <div class="accordion-item border mb-2 rounded shadow-sm">
                        <h2 class="accordion-header" id="sgHeading3">
                            <button class="accordion-button collapsed rounded"
                                    type="button"
                                    data-bs-toggle="collapse"
                                    data-bs-target="#sgCollapse3"
                                    aria-expanded="false"
                                    aria-controls="sgCollapse3">
                                <span class="badge bg-primary me-2">3</span>
                                <?= __('MISP Instances') ?>
                            </button>
                        </h2>
                        <div id="sgCollapse3"
                            class="accordion-collapse collapse"
                            aria-labelledby="sgHeading3"
                            data-bs-parent="#sgAccordion">
                            <div class="accordion-body">

                                <!-- Roaming -->
                                <div class="mb-3 form-check form-switch">
                                    <input type="checkbox" class="form-check-input" id="SharingGroupRoaming" value="1">
                                    <label class="form-check-label fw-semibold" for="SharingGroupRoaming">
                                        <?= __('Enable roaming mode') ?>
                                    </label>
                                    <div class="form-text">
                                        <?= __('Roaming mode passes the event to any connected instance where the sync connection is tied to an organisation in the SG. Prefer listing instances explicitly.') ?>
                                    </div>
                                </div>

                                <!-- Server selector -->
                                <div id="serverList">
                                    <div class="mb-3">
                                        <label class="form-label fw-semibold"><?= __('Add instance') ?></label>
                                        <?= $this->Form->select('sg_server', array_combine(
                                            array_column(array_column($availableServers ?? [], 'Server'), 'id'),
                                            array_column(array_column($availableServers ?? [], 'Server'), 'name')
                                        ), [
                                            'empty'            => true,
                                            'class'            => 'form-select tom-select bg-light',
                                            'id'               => 'sg-server-select',
                                            'data-placeholder' => __('Search instances…'),
                                        ]) ?>
                                    </div>

                                    <!-- Instances table -->
                                    <div class="table-responsive">
                                        <table class="table table-sm table-hover align-middle">
                                            <thead class="table-light">
                                                <tr>
                                                    <th><?= __('Name') ?></th>
                                                    <th><?= __('URL') ?></th>
                                                    <th><?= __('All orgs') ?></th>
                                                    <th><?= __('Actions') ?></th>
                                                </tr>
                                            </thead>
                                            <tbody id="servers_table_body"></tbody>
                                        </table>
                                    </div>
                                </div>

                                <div class="d-flex justify-content-between mt-3">
                                    <button type="button" class="btn btn-outline-secondary sg-prev" data-prev="sgCollapse2">
                                        <i class="fas fa-chevron-up me-1"></i><?= __('Previous') ?>
                                    </button>
                                    <button type="button" class="btn btn-primary sg-next" data-next="sgCollapse4">
                                        <?= __('Next') ?> <i class="fas fa-chevron-down ms-1"></i>
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- ===================== STEP 4 : SUMMARY & SAVE ===================== -->
                    <div class="accordion-item border mb-2 rounded shadow-sm">
                        <h2 class="accordion-header" id="sgHeading4">
                            <button class="accordion-button collapsed rounded"
                                    type="button"
                                    data-bs-toggle="collapse"
                                    data-bs-target="#sgCollapse4"
                                    aria-expanded="false"
                                    aria-controls="sgCollapse4">
                                <span class="badge bg-success me-2">4</span>
                                <?= __('Summary & Save') ?>
                            </button>
                        </h2>
                        <div id="sgCollapse4"
                            class="accordion-collapse collapse"
                            aria-labelledby="sgHeading4"
                            data-bs-parent="#sgAccordion">
                            <div class="accordion-body">

                                <div class="alert alert-light border">
                                    <p class="mb-2">
                                        <strong><?= __('General:') ?></strong>
                                        <?= __('You are about to create the') ?>
                                        <strong class="text-danger" id="summarytitle">—</strong>
                                        <?= __('sharing group, releasable to') ?>
                                        <strong class="text-danger" id="summaryreleasable">—</strong>.
                                    </p>
                                    <p class="mb-2" id="localText">
                                        <strong><?= __('Local organisations:') ?></strong>
                                        <?= __('Visible to') ?>
                                        <strong class="text-danger" id="summarylocal">—</strong>,
                                        <?= __('of which') ?>
                                        <strong class="text-danger" id="summarylocalextend">—</strong>
                                        <?= __('can extend the sharing group.') ?>
                                    </p>
                                    <p class="mb-2" id="externalText">
                                        <strong><?= __('External organisations:') ?></strong>
                                        <?= __('Also visible to') ?>
                                        <strong class="text-danger" id="summaryexternal">—</strong>,
                                        <?= __('of which') ?>
                                        <strong class="text-danger" id="summaryexternalextend">—</strong>
                                        <?= __('can extend the sharing group.') ?>
                                    </p>
                                    <p class="mb-0" id="synchronisationText">
                                        <strong><?= __('Synchronisation:') ?></strong>
                                        <?= __('Events are automatically pushed to:') ?>
                                        <strong class="text-danger" id="summaryservers">—</strong>
                                    </p>
                                </div>

                                <p class="text-muted small">
                                    <?= __('Review the information above. Go back to any previous section to make changes, or click Submit to create the sharing group.') ?>
                                </p>

                                <div class="d-flex justify-content-between mt-3">
                                    <button type="button" class="btn btn-outline-secondary sg-prev" data-prev="sgCollapse3">
                                        <i class="fas fa-chevron-up me-1"></i><?= __('Previous') ?>
                                    </button>
                                    <button type="button"
                                            class="btn btn-success"
                                            id="sg-submit-btn">
                                        <i class="fas fa-check me-1"></i><?= __('Submit') ?>
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

    <!-- ── FOOTER ─────────────────────────────────────────────── -->
    <div class="d-flex justify-content-between align-items-center
                mt-4 pt-3 flex-wrap gap-2">
        <div class="text-muted" style="font-size:.75rem;">
            <?php if ($edit && !empty($sharingGroup['SharingGroup']['id'])): ?>
                <?= __('Sharing group') ?>:
                <strong class="text-body">#<?= h($sharingGroup['SharingGroup']['id']) ?></strong>
                <?php if (!empty($sharingGroup['SharingGroup']['name'])): ?>
                    &nbsp;|&nbsp;
                    <strong class="text-body"><?= h($sharingGroup['SharingGroup']['name']) ?></strong>
                <?php endif; ?>
            <?php else: ?>
                <i class="fas fa-circle-info me-1" style="font-size:.65rem;"></i>
                <?= __('Your own organisation and this instance are included by default.') ?>
            <?php endif; ?>
        </div>
        <div class="d-flex gap-2">
            <button type="button" class="btn btn-outline-secondary btn-sm"
                    data-bs-dismiss="modal">
                <i class="fas fa-times me-1"></i><?= __('Discard') ?>
            </button>
            <!--
                Delegates to the wizard's own Submit (step 4), which is what
                initSharingGroupForm() binds the payload build and submit to.
            -->
            <button type="button" class="btn btn-primary btn-sm"
                    onclick="var b = document.getElementById('sg-submit-btn'); if (b) { b.click(); }">
                <i class="fas fa-<?= $edit ? 'floppy-disk' : 'circle-plus' ?> me-1"></i>
                <?= $edit ? __('Save Changes') : __('Add Sharing Group') ?>
            </button>
        </div>
    </div>

    <?= $this->Form->input('json', [
        'style'  => 'display:none;',
        'label'  => false,
        'div'    => false,
        'id'     => 'SharingGroupJson',
        'value'  => '',
    ]) ?>

</div>

<?php echo $this->Form->end(); ?>


<script>
<?php if ($edit && !empty($sharingGroup)): ?>
var sgInitData = {
    sharingGroup: {
        name:          <?= json_encode($sharingGroup['SharingGroup']['name']) ?>,
        releasability: <?= json_encode($sharingGroup['SharingGroup']['releasability'] ?? '') ?>,
        description:   <?= json_encode($sharingGroup['SharingGroup']['description']  ?? '') ?>,
        active:        <?= !empty($sharingGroup['SharingGroup']['active'])  ? 'true' : 'false' ?>,
        roaming:       <?= !empty($sharingGroup['SharingGroup']['roaming']) ? 'true' : 'false' ?>,
    },
    organisations: <?= json_encode(array_map(function($sgo) use ($user) {
        $isCurrentOrg = ($sgo['Organisation']['id'] == $user['org_id']);
        return [
            'id'        => $sgo['Organisation']['id'],
            'name'      => $sgo['Organisation']['name'],
            'type'      => !empty($sgo['Organisation']['local']) ? 'local' : 'external',
            'uuid'      => $sgo['Organisation']['uuid'] ?? '',
            'extend'    => !empty($sgo['extend']),
            'removable' => !$isCurrentOrg,
        ];
    }, $sharingGroup['SharingGroupOrg'] ?? [])) ?>,
    servers: <?= json_encode(array_map(function($sgs) use ($localInstance) {
        $serverId = $sgs['server_id'];
        $isLocal  = ($serverId == 0);
        return [
            'id'        => $isLocal ? 0 : ($sgs['Server']['id'] ?? $serverId),
            'name'      => $isLocal ? __('Local instance') : ($sgs['Server']['name'] ?? ''),
            'url'       => $isLocal ? $localInstance       : ($sgs['Server']['url']  ?? ''),
            'all_orgs'  => !empty($sgs['all_orgs']),
            'removable' => !$isLocal,
        ];
    }, $sharingGroup['SharingGroupServer'] ?? [])) ?>,
};
<?php else: ?>
var sgInitData = null;
var sgDefaultOrg = <?= json_encode([
    'id'        => $user['Organisation']['id'],
    'name'      => $user['Organisation']['name'],
    'type'      => 'local',
    'uuid'      => $user['Organisation']['uuid'] ?? '',
    'extend'    => true,
    'removable' => false,
]) ?>;
var sgDefaultServer = <?= json_encode([
    'id'        => 0,
    'name'      => __('Local instance'),
    'url'       => $localInstance,
    'all_orgs'  => false,
    'removable' => false,
]) ?>;
<?php endif; ?>

var sgOrgMeta = <?= json_encode(array_reduce($localOrgs ?? [], function($carry, $o) {
    $carry[$o['Organisation']['id']] = [
        'uuid' => $o['Organisation']['uuid'],
        'type' => 'local',
    ];
    return $carry;
}, array_reduce($externalOrgs ?? [], function($carry, $o) {
    $carry[$o['Organisation']['id']] = [
        'uuid' => $o['Organisation']['uuid'],
        'type' => 'external',
    ];
    return $carry;
}, []))) ?>;

var sgServerMeta = <?= json_encode(array_reduce($availableServers ?? [], function($carry, $s) {
    $carry[$s['Server']['id']] = ['url' => $s['Server']['url']];
    return $carry;
}, [])) ?>;
</script>