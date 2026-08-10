<?php
$edit = $this->request->params['action'] === 'edit';

echo $this->Form->create('Server', [
    'type' => 'file',
    'class' => 'needs-validation',
    'id' => $edit ? 'ServerEditForm' : 'ServerAddForm',
    'novalidate' => true,
    'data-server-id' => $edit && !empty($server['Server']['id'])
        ? h($server['Server']['id'])
        : '',
]);

?>

<!-- ── MODAL HEADER ─────────────────────────────────────────── -->
<div class="px-4 pt-3 pb-3 d-flex align-items-center justify-content-between"
     style="background:rgba(24,146,177,.06);
            border-bottom:2px solid var(--primary);">
    <div>
        <div class="text-primary text-uppercase fw-semibold mb-1"
             style="font-size:.58rem; letter-spacing:.12em; opacity:.85;">
            <?= __('Servers') ?>
        </div>
        <h4 class="mb-0 fw-bold d-flex align-items-center gap-2">
            <i class="fas fa-<?= $edit ? 'pen-to-square' : 'circle-plus' ?> text-primary"
               style="font-size:1.25rem;"></i>
            <?= $edit ? __('Edit Server') : __('Add Server') ?>
        </h4>
        <p class="text-muted mb-0" style="font-size:.75rem;">
            <?= __('Configure remote instance connection, ownership and synchronisation options.') ?>
        </p>
    </div>
    <i class="fas fa-server text-primary" style="font-size:2rem; opacity:.45;"></i>
</div>

<div class="container-fluid px-4 py-4">

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

                                <div class="row g-3">
                                    <div class="col-12 col-lg-6">
                                        <?= $this->Form->label('url', __('Base URL'), ['class' => 'form-label fw-semibold']) ?>
                                        <?= $this->Form->control('url', [
                                            'label' => false,
                                            'class' => 'form-control bg-light',
                                            'placeholder' => 'https://misp.example.org'
                                        ]) ?>
                                    </div>
                                    <div class="col-12 col-lg-6">
                                        <?= $this->Form->label('name', __('Instance name'), ['class' => 'form-label fw-semibold']) ?>
                                        <?= $this->Form->control('name', [
                                            'label' => false,
                                            'class' => 'form-control bg-light',
                                            'placeholder' => __('Remote instance name')
                                        ]) ?>
                                    </div>
                                </div>

                                <div id="InternalDiv" class="alert alert-warning mt-4 mb-0">
                                    <p class="mb-2">
                                        <?= __('You can set this instance up as an internal instance by checking the checkbox below. This means that synchronisation will not be automatically degraded. Use only if both instances are under your control and host organisation matches.') ?>
                                    </p>
                                    <div class="form-check">
                                        <?= $this->Form->checkbox('internal', ['class' => 'form-check-input']) ?>
                                        <?= $this->Form->label('internal', __('Internal instance'), ['class' => 'form-check-label']) ?>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- ===================== STEP 2 : Ownership & Credentials ===================== -->
                    <div class="accordion-item border mb-2 rounded shadow-sm">
                        <h2 class="accordion-header" id="sgHeading2">
                            <button class="accordion-button collapsed rounded"
                                    type="button"
                                    data-bs-toggle="collapse"
                                    data-bs-target="#sgCollapse2"
                                    aria-expanded="false"
                                    aria-controls="sgCollapse2">
                                <span class="badge bg-primary me-2">2</span>
                                <?= __('Instance ownership and credentials') ?>
                            </button>
                        </h2>
                        <div id="sgCollapse2"
                            class="accordion-collapse collapse"
                            aria-labelledby="sgHeading2"
                            data-bs-parent="#sgAccordion">
                            <div class="accordion-body">

                                <p class="text-muted mb-3">
                                    <?= __('Information about the organisation receiving the events (typically the remote host organisation).') ?>
                                </p>

                                <div class="row g-3 align-items-end">
                                    <!-- Type -->
                                    <div class="col-12 col-lg-6">
                                        <?= $this->Form->label('organisation_type', __('Organisation Type'), ['class' => 'form-label fw-semibold']) ?>
                                        <?= $this->Form->select('organisation_type', $organisationOptions, [
                                            'empty' => __('Select a type of organisation...'),
                                            'class' => 'form-select tom-select bg-light',
                                            'id' => 'ServerOrganisationType',
                                            'value' => isset($oldRemoteSetting) ? $oldRemoteSetting : '',
                                        ])?>
                                    </div>
                                </div>

                                <div class="row g-3 mt-0">
                                    <div id="ServerLocalContainer" class="col-12 col-lg-6 hiddenField" style="display:none;">
                                        <label for="ServerLocal" class="form-label fw-semibold"><?= __('Local Organisation') ?></label>
                                        <select id="ServerLocal" class="form-select tom-select bg-light">
                                            <?php foreach ($localOrganisations as $k => $v): ?>
                                                <option value="<?= h($k) ?>"<?= (!empty($oldRemoteOrg) && $k == $oldRemoteOrg) ? ' selected="selected"' : '' ?>>
                                                    <?= h($v) ?>
                                                </option>
                                            <?php endforeach; ?>
                                        </select>
                                    </div>
                                    <div id="ServerExternalContainer" class="col-12 col-lg-6 hiddenField" style="display:none;">
                                        <label for="ServerExternal" class="form-label fw-semibold"><?= __('External Organisation') ?></label>
                                        <select id="ServerExternal" class="form-select tom-select bg-light">
                                            <?php foreach ($externalOrganisations as $k => $v): ?>
                                                <option value="<?= h($k) ?>"<?= (!empty($oldRemoteOrg) && $k == $oldRemoteOrg) ? ' selected="selected"' : '' ?>>
                                                    <?= h($v) ?>
                                                </option>
                                            <?php endforeach; ?>
                                        </select>
                                    </div>
                                    <div id="ServerExternalNameContainer" class="col-12 col-lg-6 hiddenField" style="display:none;">
                                        <label for="ServerExternalName" class="form-label fw-semibold"><?= __('Remote Organisation\'s Name') ?></label>
                                        <input
                                            type="text"
                                            id="ServerExternalName"
                                            class="form-control bg-light"
                                            value="<?= !empty($this->request->data['Server']['external_name']) ? h($this->request->data['Server']['external_name']) : '' ?>"
                                        >
                                    </div>
                                    <div id="ServerExternalUuidContainer" class="col-12 col-lg-6 hiddenField" style="display:none;">
                                        <label for="ServerExternalUuid" class="form-label fw-semibold"><?= __('Remote Organisation\'s UUID') ?></label>
                                        <input
                                            type="text"
                                            id="ServerExternalUuid"
                                            class="form-control bg-light"
                                            value="<?= !empty($this->request->data['Server']['external_uuid']) ? h($this->request->data['Server']['external_uuid']) : '' ?>"
                                        >
                                    </div>
                                </div>

                                <div id="AuthkeyContainer" class="mt-4">
                                    <p class="text-muted mb-2">
                                        <?= __('Use the remote sync user API key (Global actions -> My profile on remote MISP).') ?>
                                    </p>
                                    <?= $this->Form->label('authkey', __('Authentication key'), ['class' => 'form-label fw-semibold']) ?>
                                    <?= $this->Form->control('authkey', [
                                        'label' => false,
                                        'type' => 'text',
                                        'class' => 'form-control bg-light',
                                        'autocomplete' => 'off',
                                        'placeholder' => __('Leave empty to keep current key')
                                    ]) ?>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- ===================== STEP 3 : Synchronisation Methods ===================== -->
                    <div class="accordion-item border mb-2 rounded shadow-sm">
                        <h2 class="accordion-header" id="sgHeading3">
                            <button class="accordion-button collapsed rounded"
                                    type="button"
                                    data-bs-toggle="collapse"
                                    data-bs-target="#sgCollapse3"
                                    aria-expanded="false"
                                    aria-controls="sgCollapse3">
                                <span class="badge bg-primary me-2">3</span>
                                <?= __('Enabled synchronisation methods') ?>
                            </button>
                        </h2>
                        <div id="sgCollapse3"
                            class="accordion-collapse collapse"
                            aria-labelledby="sgHeading3"
                            data-bs-parent="#sgAccordion">
                            <div class="accordion-body">
                                <div class="row g-2">
                                    <?php
                                    $syncFields = [
                                        'push' => __('Push'),
                                        'pull' => __('Pull'),
                                        'push_sightings' => __('Push sightings'),
                                        'caching_enabled' => __('Enable cache'),
                                        'push_galaxy_clusters' => __('Push clusters'),
                                        'pull_galaxy_clusters' => __('Pull clusters'),
                                        'push_analyst_data' => __('Push analyst data'),
                                        'pull_analyst_data' => __('Pull analyst data')
                                    ];
                                    foreach ($syncFields as $name => $label):
                                    ?>
                                        <div class="col-12 col-md-6">
                                            <div class="form-check">
                                                <?= $this->Form->checkbox($name, ['class' => 'form-check-input']) ?>
                                                <?= $this->Form->label($name, $label, ['class' => 'form-check-label']) ?>
                                            </div>
                                        </div>
                                    <?php endforeach; ?>
                                </div>
                            </div>
                        </div>
                    </div>


                    <!-- ===================== STEP 4 : Misc Settings ===================== -->
                    <div class="accordion-item border mb-2 rounded shadow-sm">
                        <h2 class="accordion-header" id="sgHeading4">
                            <button class="accordion-button collapsed rounded"
                                    type="button"
                                    data-bs-toggle="collapse"
                                    data-bs-target="#sgCollapse4"
                                    aria-expanded="false"
                                    aria-controls="sgCollapse4">
                                <span class="badge bg-primary me-2">4</span>
                                <?= __('Misc settings') ?>
                            </button>
                        </h2>
                        <div id="sgCollapse4"
                            class="accordion-collapse collapse"
                            aria-labelledby="sgHeading4"
                            data-bs-parent="#sgAccordion">
                            <div class="accordion-body">
                                <div class="row g-2">
                                    <?php
                                    $miscFields = [
                                        'unpublish_event' => __('Unpublish event when pushing'),
                                        'publish_without_email' => __('Publish without email'),
                                        'self_signed' => __('Allow self-signed certificates'),
                                        'skip_proxy' => __('Skip proxy (if applicable)'),
                                        'remove_missing_tags' => __('Remove missing tags (not recommended)'),
                                    ];
                                    foreach ($miscFields as $name => $label):
                                    ?>
                                        <div class="col-12 col-md-6">
                                            <div class="form-check">
                                                <?= $this->Form->checkbox($name, ['class' => 'form-check-input']) ?>
                                                <?= $this->Form->label($name, $label, ['class' => 'form-check-label']) ?>
                                            </div>
                                        </div>
                                    <?php endforeach; ?>
                                </div>

                                <hr class="my-4">

                                <!-- ===== Certificates ===== -->
                                <p class="fw-semibold mb-1">
                                    <i class="fas fa-lock me-1"></i><?= __('Certificate files') ?>
                                </p>
                                <p class="text-muted small mb-3">
                                    <?= __('Drop a .pem file or click the zone to browse.') //Accepted: .pem, .crt, .key') ?>
                                </p>

                                <div class="row g-3">
                                    <!-- Client certificate -->
                                    <div class="col-12 col-md-6">
                                        <label class="form-label fw-semibold">
                                            <?= __('Client certificate') ?>
                                            <span class="fw-normal text-muted">(submitted_client_cert)</span>
                                        </label>
                                        <div class="pem-dropzone"
                                            id="pemDrop-client"
                                            data-target="ServerSubmittedClientCert"
                                            role="button"
                                            tabindex="0"
                                            aria-label="<?= __('Upload client certificate') ?>">
                                            <div class = "d-flex align-items-center flex-column">
                                                <i class="fas fa-upload pem-icon"></i>
                                                <span class="pem-hint"><?= __('Drop .pem or click to browse') ?></span>
                                                <div class="pem-filename d-none"></div>
                                            </div>
                                        </div>
                                        <?= $this->Form->input('Server.submitted_client_cert', [
                                            'label'    => false,
                                            'type'     => 'file',
                                            'accept'   => '.pem',
                                            'class'    => 'pem-input visually-hidden',
                                            'id'       => 'ServerSubmittedClientCert',
                                        ]) ?>
                                        <?php if (!empty($server['Server']['client_cert_file'])): ?>
                                            <div class="pem-existing"
                                                data-zone="pemDrop-client"
                                                data-input="ServerSubmittedClientCert"
                                                data-delete-field="ServerDeleteClientCert"
                                                data-filename="<?= h($server['Server']['client_cert_file']) ?>">
                                            </div>
                                        <?php endif; ?>
                                    </div>

                                    <!-- CA / Server certificate -->
                                    <div class="col-12 col-md-6">
                                        <label class="form-label fw-semibold">
                                            <?= __('Server (CA) certificate') ?>
                                            <span class="fw-normal text-muted">(submitted_cert)</span>
                                        </label>
                                        <div class="pem-dropzone"
                                            id="pemDrop-server"
                                            data-target="ServerSubmittedCert"
                                            role="button"
                                            tabindex="0"
                                            aria-label="<?= __('Upload server certificate') ?>">
                                            <div class = "d-flex align-items-center flex-column">
                                                <i class="fas fa-upload pem-icon"></i>
                                                <span class="pem-hint"><?= __('Drop .pem or click to browse') ?></span>
                                                <span class="pem-filename d-none"></span>
                                            </div>
                                        </div>
                                        <?= $this->Form->input('Server.submitted_cert', [
                                            'label'    => false,
                                            'type'     => 'file',
                                            'accept'   => '.pem',
                                            'class'    => 'pem-input visually-hidden',
                                            'id'       => 'ServerSubmittedCert',
                                        ]) ?>
                                        <?php if (!empty($server['Server']['cert_file'])): ?>
                                            <div class="pem-existing"
                                                data-zone="pemDrop-server"
                                                data-input="ServerSubmittedCert"
                                                data-delete-field="ServerDeleteCert"
                                                data-filename="<?= h($server['Server']['cert_file']) ?>">
                                            </div>
                                        <?php endif; ?>

                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- ===================== STEP 5 : Sync Rules ===================== -->
                    <div class="accordion-item border mb-2 rounded shadow-sm">
                        <h2 class="accordion-header" id="sgHeading5">
                            <button class="accordion-button collapsed rounded"
                                    type="button"
                                    data-bs-toggle="collapse"
                                    data-bs-target="#sgCollapse5"
                                    aria-expanded="false"
                                    aria-controls="sgCollapse5">
                                <span class="badge bg-primary me-2">5</span>
                                <?= __('Sync rules') ?>
                            </button>
                        </h2>
                        <div id="sgCollapse5"
                            class="accordion-collapse collapse"
                            aria-labelledby="sgHeading5"
                            data-bs-parent="#sgAccordion">

                            <div class="accordion-body">
                                <ul class="nav nav-tabs mb-4" id="syncRulesTabs" role="tablist">
                                    <li class="nav-item" role="presentation">
                                        <button class="nav-link active"
                                                id="tab-push"
                                                data-bs-toggle="tab"
                                                data-bs-target="#tabPane-push"
                                                type="button"
                                                role="tab"
                                                aria-controls="tabPane-push"
                                                aria-selected="true">
                                            <i class="fas fa-arrow-up me-1"></i>
                                            <?= __('Push rules') ?>
                                        </button>
                                    </li>
                                    <li class="nav-item" role="presentation">
                                        <button class="nav-link"
                                                id="tab-pull"
                                                data-bs-toggle="tab"
                                                data-bs-target="#tabPane-pull"
                                                type="button"
                                                role="tab"
                                                aria-controls="tabPane-pull"
                                                aria-selected="false">
                                            <i class="fas fa-arrow-down me-1"></i>
                                            <?= __('Pull rules') ?>
                                        </button>
                                    </li>
                                </ul>

                                <div class="tab-content" id="syncRulesTabContent">

                                    <?php
                                    // Decode existing rules
                                    $existingRules = ['push' => [], 'pull' => []];
                                    if ($edit && !empty($server['Server']['push_rules'])) {
                                        $decoded = json_decode($server['Server']['push_rules'], true);
                                        if (is_array($decoded)) $existingRules['push'] = $decoded;
                                    }
                                    if ($edit && !empty($server['Server']['pull_rules'])) {
                                        $decoded = json_decode($server['Server']['pull_rules'], true);
                                        if (is_array($decoded)) $existingRules['pull'] = $decoded;
                                    }

                                    // Mapping table for listType → key in the stored JSON
                                    $listTypeToKey = ['allowedlist' => 'OR', 'blockedlist' => 'NOT'];

                                    $syncRuleSections = [
                                        'push' => [__('Push rules'), __('Configure the rules to be applied when PUSHing data to the server')],
                                        'pull' => [__('Pull rules'), __('Configure the rules to be applied when PULLing data from the server')],
                                    ];
                                    foreach ($syncRuleSections as $direction => $directionLabel):
                                        $isActive = $direction === 'push' ? 'show active' : '';
                                    ?>

                                    <div class="tab-pane fade <?= $isActive ?>"
                                        id="tabPane-<?= $direction ?>"
                                        role="tabpanel"
                                        aria-labelledby="tab-<?= $direction ?>">

                                        <p class="text-muted mb-3"><?= $directionLabel[1] ?></p>

                                        <div class="row g-3 mb-4">
                                            <?php if ($direction === 'pull'): ?>
                                                <div id="syncRulePullAlert" class="mb-3">
                                                    <?php if ($edit && !empty($server['Server']['id'])): ?>
                                                        <div class="alert alert-info alert-sm d-flex align-items-center gap-2 sync-pull-fetching">
                                                            <i class="fas fa-spinner fa-spin"></i>
                                                            <?= __('Fetching tags and organisations from the remote server…') ?>
                                                        </div>
                                                        <div class="alert alert-success alert-sm sync-pull-success d-none">
                                                            <i class="fas fa-check-circle me-1"></i>
                                                            <?= __('Tags and organisations loaded from remote server.') ?>
                                                        </div>
                                                        <div class="alert alert-warning alert-sm sync-pull-error d-none">
                                                            <i class="fas fa-exclamation-triangle me-1"></i>
                                                            <span class="sync-pull-error-msg"></span>
                                                        </div>
                                                    <?php else: ?>
                                                        <div class="alert alert-warning alert-sm">
                                                            <i class="fas fa-exclamation-triangle me-1"></i>
                                                            <?= __('Save the server first to fetch remote tags and organisations for pull rules.') ?>
                                                        </div>
                                                    <?php endif; ?>
                                                </div>
                                            <?php endif; ?>

                                            <?php
                                            //Adapts the lists provided by the controller for the select inputs
                                            $tag_list = [];
                                            foreach ($allTags as $tag) {
                                                $tag_list[$tag['id']] = $tag['name'];
                                            }
                                            $organisation_list = [];
                                            foreach ($allOrganisations as $organisation) {
                                                $organisation_list[$organisation['id']] = $organisation['name'];
                                            }

                                            $object_list = [];
                                            foreach ($allObjectTypes as $object) {
                                                $object_list[$object['id']] = $object['name'];
                                            }

                                            $ruleSections = [
                                                'tags' => ['label' => __('Tags'),         'icon' => 'tag',      'select' => $tag_list ?? []],
                                                'orgs' => ['label' => __('Organisations'), 'icon' => 'building', 'select' => $organisation_list ?? []],
                                            ];
                                            foreach ($ruleSections as $ruleType => $ruleMeta):
                                                foreach (['allowedlist', 'blockedlist'] as $listType):
                                                    $fieldKey    = "{$direction}_{$ruleType}_{$listType}";
                                                    $isPullRemote = ($direction === 'pull');
                                            ?>

                                            <div class="col-12 col-lg-6">
                                                <div class="sync-rule-box border rounded p-3"
                                                    data-direction="<?= $direction ?>"
                                                    data-type="<?= $ruleType ?>"
                                                    data-list="<?= $listType ?>">

                                                    <div class="d-flex align-items-center gap-2 mb-2">
                                                        <i class="fas fa-<?= $ruleMeta['icon'] ?> text-muted"></i>
                                                        <span class="fw-semibold" style="font-size:.875rem;">
                                                            <?= $ruleMeta['label'] ?>
                                                        </span>
                                                        <span class="ms-auto badge <?= $listType === 'allowedlist' ? 'text-bg-success' : 'text-bg-danger' ?>"
                                                            style="font-size:.7rem;">
                                                            <?= $listType === 'allowedlist' ? __('Allowedlist') : __('Blockedlist') ?>
                                                        </span>
                                                    </div>

                                                    <?php if (!empty($ruleMeta['select'])): ?>
                                                    <div class="mb-2">
                                                        <?= $this->Form->select($fieldKey . '_select',
                                                            $isPullRemote ? [] : $ruleMeta['select'],
                                                            [
                                                                'multiple'         => true,
                                                                'class'            => 'form-select tom-select sync-rule-select bg-light',
                                                                'data-placeholder' => $isPullRemote
                                                                    ? __('Fetching from remote server…')
                                                                    : __('Search existing…'),
                                                                'data-field-key'   => $fieldKey,
                                                                'data-remote'      => $isPullRemote ? 'true' : 'false',
                                                                'id'               => 'SyncRule_' . $fieldKey . '_select',
                                                                'disabled'         => $isPullRemote,
                                                            ]
                                                        ) ?>
                                                    </div>
                                                    <?php endif; ?>

                                                    <div class="input-group input-group-sm mb-2">
                                                        <input type="text"
                                                            class="form-control sync-rule-freetext bg-light"
                                                            placeholder="<?= __('Or use a freetext name') ?>"
                                                            data-field-key="<?= $fieldKey ?>">
                                                        <button class="btn btn-outline-secondary sync-rule-add-btn"
                                                                type="button"
                                                                data-field-key="<?= $fieldKey ?>"
                                                                aria-label="<?= __('Add') ?>">
                                                            <i class="fas fa-plus"></i>
                                                        </button>
                                                    </div>

                                                    <?php
                                                    // Explanation of the different pills displayed
                                                    $contextLabel = match(true) {
                                                        $ruleType === 'tags' && $listType === 'allowedlist' => __('Events with the following tags allowed:'),
                                                        $ruleType === 'tags' && $listType === 'blockedlist' => __('Events with the following tags blocked:'),
                                                        $ruleType === 'orgs' && $listType === 'allowedlist' => __('Events from the following organisations allowed:'),
                                                        default                                             => __('Events from the following organisations blocked:'),
                                                    };
                                                    ?>
                                                    <p class="sync-rule-label text-muted fs-6 d-none mb-1" style="font-size:.75rem;font-weight:500;">
                                                        <?= $contextLabel ?>
                                                    </p>

                                                    <div class="sync-rule-pills d-flex flex-wrap gap-1"
                                                        id="SyncRulePills_<?= $fieldKey ?>">
                                                    </div>


                                                    <?php
                                                        $jsonKey    = $listTypeToKey[$listType];  // category 'OR' or 'NOT'
                                                        $initValues = $existingRules[$direction][$ruleType][$jsonKey] ?? [];
                                                        $initJson   = json_encode(array_values($initValues));
                                                    ?>
                                                    <input type="hidden"
                                                        id="SyncRuleJson_<?= $fieldKey ?>"
                                                        value="<?= h($initJson) ?>">
                                                </div>
                                            </div>

                                            <?php
                                                endforeach;
                                            endforeach;
                                            ?>
                                        </div>

                                        <!-- ===== Additional JSON filter parameters ===== -->
                                        <?php if ($direction === 'pull'): ?>
                                        <div class="mb-4">
                                            <label for="SyncRulePullUrlParams" class="form-label fw-semibold">
                                                <i class="fas fa-filter me-1"></i>
                                                <?= __('Additional sync parameters') ?>
                                            </label>
                                            <p class="text-muted small mb-2">
                                                <?= __('Optional JSON filters based on the event index (e.g. %s).', '<code>{"timestamp": "30d"}</code>') ?>
                                            </p>
                                            <textarea
                                                id="SyncRulePullUrlParams"
                                                class="form-control bg-light"
                                                rows="4"
                                                spellcheck="false"><?php
                                                    $urlParams = $existingRules['pull']['url_params'] ?? '';
                                                    // url_params is stored as a JSON string in the database
                                                    if (is_string($urlParams) && !empty($urlParams)) {
                                                        $decoded = json_decode($urlParams, true);
                                                        echo $decoded !== null ? json_encode($decoded, JSON_PRETTY_PRINT) : h($urlParams);
                                                    }
                                                ?></textarea>
                                            <div id="SyncRulePullUrlParamsError" class="invalid-feedback"></div>
                                        </div>
                                        <?php endif; ?>

                                        <!-- ===== Type filtering (enable_synchronisation_filtering_on_type) ===== -->
                                        <?php
                                            $initTypeAttributes = $existingRules[$direction]['type_attributes']['NOT'] ?? [];
                                            $initTypeObjects    = $existingRules[$direction]['type_objects']['NOT']    ?? [];
                                            $hasTypeFiltering   = !empty($initTypeAttributes) || !empty($initTypeObjects);
                                        ?>
                                        <?php if (!empty(Configure::read('MISP.enable_synchronisation_filtering_on_type'))): ?>
                                        <div class="mt-4" id="typeFilteringSection_<?= $direction ?>">

                                            <div class="form-check form-switch mb-2">
                                                <input class="form-check-input type-filtering-toggle"
                                                    type="checkbox"
                                                    role="switch"
                                                    id="typeFilteringEnable_<?= $direction ?>"
                                                    data-direction="<?= $direction ?>"
                                                    <?= $hasTypeFiltering ? 'checked' : '' ?>>
                                                <label class="form-check-label fw-semibold"
                                                       for="typeFilteringEnable_<?= $direction ?>">
                                                    <?= __('Enable type filtering') ?>
                                                </label>
                                            </div>

                                            <div class="type-filtering-warning <?= $hasTypeFiltering ? '' : 'd-none' ?>" id="typeFilteringWarning_<?= $direction ?>">
                                                <div class="alert alert-danger">
                                                    <strong><?= __('Warning!') ?></strong>
                                                    <?= __('Use this feature only if you know exactly what you are doing as it might introduce unwanted behaviour:') ?>
                                                    <ul class="mb-2">
                                                        <li><?= __('This instance will potentially receive incomplete events (missing the filtered-out types)') ?></li>
                                                        <li><?= __('If later on you were to decide to have the previously filtered types included, the only way for this instance to receive them is to completely delete the affected events, as a full sync is needed') ?></li>
                                                        <li><?= __('Any instances synchronising with this instance will also receive incomplete events') ?></li>
                                                    </ul>
                                                    <strong><?= __('Any instance being synchronised with this one will also be affected by these shortcomings!') ?></strong>

                                                    <div class="form-check mt-2">
                                                        <input class="form-check-input type-filtering-confirm"
                                                            type="checkbox"
                                                            id="typeFilteringConfirm_<?= $direction ?>"
                                                            data-direction="<?= $direction ?>"
                                                            <?= $hasTypeFiltering ? 'checked' : '' ?>>
                                                        <label class="form-check-label"
                                                               for="typeFilteringConfirm_<?= $direction ?>">
                                                            <?= __('I understand the caveats mentioned above resulting from the use of these filters') ?>
                                                        </label>
                                                    </div>
                                                </div>

                                                <div class="type-filtering-selects <?= $hasTypeFiltering ? '' : 'd-none' ?>" id="typeFilteringSelects_<?= $direction ?>">
                                                    <div class="row g-3">
                                                        <div class="col-12 col-lg-6">
                                                            <label class="form-label fw-semibold">
                                                                <span class="misp-icon misp-icon-attribute misp-simple me-1 text-muted"></span>
                                                                <?= __('Attribute types to block') ?>
                                                            </label>
                                                            <?= $this->Form->select(
                                                                $direction . '_type_attributes_NOT_select',
                                                                $allAttributeTypes,
                                                                [
                                                                    'multiple'         => true,
                                                                    'class'            => 'form-select tom-select bg-light type-filtering-select',
                                                                    'data-placeholder' => __('Select attribute types to block…'),
                                                                    'data-direction'   => $direction,
                                                                    'data-scope'       => 'type_attributes',
                                                                    'id'               => 'TypeFilterSelect_' . $direction . '_attributes',
                                                                ]
                                                            ) ?>
                                                            <!-- Pills -->
                                                            <div class="sync-rule-pills d-flex flex-wrap gap-1 mt-2"
                                                                 id="TypeFilterPills_<?= $direction ?>_attributes"></div>
                                                            <!-- Hidden JSON -->
                                                            <input type="hidden"
                                                                    id="TypeFilterJson_<?= $direction ?>_attributes"
                                                                    value="<?= h(json_encode(array_values($initTypeAttributes))) ?>">
                                                        </div>

                                                        <div class="col-12 col-lg-6">
                                                            <label class="form-label fw-semibold">
                                                                <span class="misp-icon misp-icon-object misp-simple me-1 text-muted"></span>
                                                                <?= __('Object types to block') ?>
                                                            </label>
                                                            <?= $this->Form->select(
                                                                $direction . '_type_objects_NOT_select',
                                                                $object_list,
                                                                [
                                                                    'multiple'         => true,
                                                                    'class'            => 'form-select tom-select bg-light type-filtering-select',
                                                                    'data-placeholder' => __('Select object types to block…'),
                                                                    'data-direction'   => $direction,
                                                                    'data-scope'       => 'type_objects',
                                                                    'id'               => 'TypeFilterSelect_' . $direction . '_objects',
                                                                ]
                                                            ) ?>
                                                            <!-- Pills -->
                                                            <div class="sync-rule-pills d-flex flex-wrap gap-1 mt-2"
                                                                 id="TypeFilterPills_<?= $direction ?>_objects"></div>
                                                            <!-- Hidden JSON -->
                                                            <input type="hidden"
                                                                id="TypeFilterJson_<?= $direction ?>_objects"
                                                                value="<?= h(json_encode(array_values($initTypeObjects))) ?>">
                                                        </div>

                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                        <?php endif; ?>

                                    </div>

                                    <?php endforeach; ?>

                                </div>
                            </div>
                        </div>
                    </div>
                </div>

    <!-- ── FOOTER ─────────────────────────────────────────────── -->
    <div class="d-flex justify-content-between align-items-center
                mt-4 pt-3 flex-wrap gap-2">
        <div class="text-muted" style="font-size:.75rem;">
            <?php if ($edit && !empty($server['Server']['id'])): ?>
                <?= __('Server') ?>:
                <strong class="text-body">#<?= h($server['Server']['id']) ?></strong>
                <?php if (!empty($server['Server']['url'])): ?>
                    &nbsp;|&nbsp;
                    <code class="text-body"><?= h($server['Server']['url']) ?></code>
                <?php endif; ?>
            <?php else: ?>
                <i class="fas fa-circle-info me-1" style="font-size:.65rem;"></i>
                <?= __('Connection settings can be tested from the server index once saved.') ?>
            <?php endif; ?>
        </div>
        <div class="d-flex gap-2">
            <button type="button" class="btn btn-outline-secondary btn-sm"
                    data-bs-dismiss="modal">
                <i class="fas fa-times me-1"></i><?= __('Discard') ?>
            </button>
            <?= $this->Form->button(
                '<i class="fas fa-' . ($edit ? 'floppy-disk' : 'circle-plus') . ' me-1"></i> '
                    . ($edit ? __('Save Changes') : __('Add Server')),
                [
                    'class' => 'btn btn-primary btn-sm',
                    'onClick' => $edit ? "serverSubmitForm('Edit')" : "serverSubmitForm('Add')",
                    'escapeTitle' => false,
                    'title' => $edit ? __('Save Changes') : __('Add Server'),
                    'aria-label' => $edit ? __('Save Changes') : __('Add Server'),
                ]
            ) ?>
        </div>
    </div>

    <?php
        echo $this->Form->input('push_rules', array('style' => 'display:none;', 'label' => false, 'div' => false));
        echo $this->Form->input('pull_rules', array('style' => 'display:none;', 'label' => false, 'div' => false));
        echo $this->Form->input('json', array('style' => 'display:none;', 'label' => false, 'div' => false));
        echo $this->Form->checkbox('delete_cert', array('style' => 'display:none;', 'label' => false, 'div' => false));
        echo $this->Form->checkbox('delete_client_cert', array('style' => 'display:none;', 'label' => false, 'div' => false));
    ?>
</div>

<?= $this->Form->end(); ?>

