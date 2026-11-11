<?php
$tpl = $data['EventTemplate'] ?? [];
$organisation = $data['Organisation'] ?? [];
$creator = $data['CreatorUser'] ?? [];

$definition = is_array($tpl['definition'] ?? null) ? $tpl['definition'] : [];
$libraryMetadata = is_array($definition['library_metadata'] ?? null)
    ? $definition['library_metadata']
    : [];

$uuid = (string)($tpl['uuid'] ?? '');
$isActive = (int)($tpl['active'] ?? 0) === 1;
$isLibraryManaged = !empty($tpl['misp_default']);
$isExposed = !empty($tpl['exposed']);
?>
<div class="card mb-3 shadow-sm">
    <div class="card-body p-4">

        <!-- NAME -->
        <div class="mb-4">
            <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Name') ?></div>
            <div class="fw-semibold fs-5 d-flex align-items-center flex-wrap gap-2">
                <?= h($tpl['name'] ?? '') ?>

                <?php if ($isActive): ?>
                    <span class="badge bg-success-subtle text-success-emphasis border border-success-subtle">
                        <i class="fas fa-circle-play me-1"></i><?= __('Active') ?>
                    </span>
                <?php else: ?>
                    <span class="badge bg-secondary-subtle text-secondary-emphasis border border-secondary-subtle"
                          title="<?= h(__('Inactive templates are not offered when creating an event.')) ?>">
                        <i class="fas fa-circle-stop me-1"></i><?= __('Inactive') ?>
                    </span>
                <?php endif; ?>

                <?php if ($isLibraryManaged): ?>
                    <span class="badge bg-info-subtle text-info-emphasis border border-info-subtle"
                          title="<?= h(__('Managed by the misp-event-templates submodule — an Update from library run overwrites local edits.')) ?>">
                        <i class="fas fa-cube me-1"></i><?= __('Library-managed') ?>
                    </span>
                <?php endif; ?>

                <?php if ($isExposed): ?>
                    <span class="badge bg-warning-subtle text-warning-emphasis border border-warning-subtle"
                          title="<?= h(__('Offered to anonymous community reporters through Draugnet.')) ?>">
                        <i class="fas fa-globe me-1"></i><?= __('Exposed to Draugnet') ?>
                    </span>
                <?php endif; ?>
            </div>
        </div>

        <!-- DESCRIPTION -->
        <div class="mb-4">
            <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Description') ?></div>
            <?php if (!empty($tpl['description'])): ?>
                <div class="bg-light border rounded p-3"><?= nl2br(h($tpl['description'])) ?></div>
            <?php else: ?>
                <div class="text-muted">&mdash;</div>
            <?php endif; ?>
        </div>

        <!-- META GRID -->
        <div class="row g-3">

            <!-- ID -->
            <div class="col-md-4">
                <div class="text-muted small text-uppercase fw-bold mb-1">ID</div>
                <div class="bg-light rounded px-2 py-1 border d-inline-block"><?= h($tpl['id'] ?? '') ?></div>
            </div>

            <!-- UUID -->
            <div class="col-md-4">
                <div class="text-muted small text-uppercase fw-bold mb-1">UUID</div>
                <div class="d-flex align-items-center gap-2">
                    <div class="bg-light rounded px-2 py-1 border font-monospace text-break"
                         style="font-size:.8rem;"><?= h($uuid) ?></div>
                    <button type="button"
                            class="btn btn-sm btn-light border-0 text-muted"
                            data-uuid="<?= h($uuid) ?>"
                            onclick="copyValueToClipboard(this.dataset.uuid, '<?= h(__('UUID copied to clipboard')) ?>')"
                            title="<?= h(__('Copy UUID')) ?>"
                            aria-label="<?= h(__('Copy UUID')) ?>">
                        <i class="fas fa-copy"></i>
                    </button>
                </div>
            </div>

            <!-- VERSION -->
            <div class="col-md-4">
                <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Version') ?></div>
                <?= $this->element('genericElementsBS5/Badges/version', [
                    'version' => $tpl['version'] ?? 0,
                ]) ?>
            </div>

            <!-- DISTRIBUTION -->
            <div class="col-md-4">
                <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Distribution') ?></div>
                <div class="py-1">
                    <?php
                    /*
                     * A template is either org-only (0) or community-wide (1) —
                     * the builder offers nothing else — so the shared badge's
                     * labels ("Your organisation only" / "This community only")
                     * read correctly here.
                     */
                    echo $this->element('genericElementsBS5/Badges/distribution', [
                        'distribution' => (int)($tpl['distribution'] ?? 0),
                        'full' => true,
                    ]);
                    ?>
                </div>
            </div>

            <!-- OWNER ORG -->
            <div class="col-md-4">
                <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Owner org') ?></div>
                <?php if (!empty($organisation['name'])): ?>
                    <div class="d-flex align-items-center gap-2">
                        <?= $this->OrgImg->getOrgLogoV2($organisation, 24, false) ?>
                        <?= h($organisation['name']) ?>
                    </div>
                <?php else: ?>
                    <div class="text-muted">&mdash;</div>
                <?php endif; ?>
            </div>

            <!-- CREATOR -->
            <div class="col-md-4">
                <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Creator') ?></div>
                <?php if (!empty($creator['email'])): ?>
                    <?php if (!empty($creator['id']) && !empty($isSiteAdmin)): ?>
                        <a class="text-decoration-none"
                           href="<?= h($baseurl . '/admin/users/view/' . (int)$creator['id']) ?>">
                            <?= h($creator['email']) ?>
                        </a>
                    <?php else: ?>
                        <?= h($creator['email']) ?>
                    <?php endif; ?>
                <?php else: ?>
                    <div class="text-muted">&mdash;</div>
                <?php endif; ?>
            </div>

            <!-- SCHEMA VERSION -->
            <div class="col-md-4">
                <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Schema version') ?></div>
                <div class="bg-light rounded px-2 py-1 border d-inline-block">
                    <?= h($definition['schema_version'] ?? '—') ?>
                </div>
            </div>

            <!-- CREATED -->
            <div class="col-md-4">
                <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Created') ?></div>
                <div><?= !empty($tpl['created']) ? h($tpl['created']) : '<span class="text-muted">&mdash;</span>' ?></div>
            </div>

            <!-- MODIFIED -->
            <div class="col-md-4">
                <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Modified') ?></div>
                <div><?= !empty($tpl['modified']) ? h($tpl['modified']) : '<span class="text-muted">&mdash;</span>' ?></div>
            </div>

        </div>

        <!-- LIBRARY PROVENANCE (submodule templates only) -->
        <?php if (!empty($libraryMetadata)): ?>
            <hr class="my-4 opacity-25">
            <div class="text-muted small text-uppercase fw-bold mb-2"><?= __('Library metadata') ?></div>
            <div class="row g-3">
                <?php if (!empty($libraryMetadata['authors'])): ?>
                    <div class="col-md-6">
                        <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Authors') ?></div>
                        <div class="d-flex flex-column gap-1">
                            <?php foreach ($libraryMetadata['authors'] as $author): ?>
                                <div class="d-flex align-items-center gap-2">
                                    <i class="fas fa-user text-muted" style="font-size:.75rem;"></i>
                                    <span><?= h($author['name'] ?? '') ?></span>
                                    <?php if (!empty($author['contact'])): ?>
                                        <span class="text-muted small"><?= h($author['contact']) ?></span>
                                    <?php endif; ?>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    </div>
                <?php endif; ?>

                <?php if (!empty($libraryMetadata['compatible_misp_version'])): ?>
                    <div class="col-md-3">
                        <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Needs MISP') ?></div>
                        <div class="bg-light rounded px-2 py-1 border d-inline-block">
                            <?= h($libraryMetadata['compatible_misp_version']) ?>
                        </div>
                    </div>
                <?php endif; ?>

                <?php if (!empty($libraryMetadata['tags'])): ?>
                    <div class="col-md-3">
                        <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Keywords') ?></div>
                        <div class="d-flex flex-wrap gap-1">
                            <?php foreach ($libraryMetadata['tags'] as $keyword): ?>
                                <span class="badge bg-body border text-body-secondary fw-normal">
                                    <?= h($keyword) ?>
                                </span>
                            <?php endforeach; ?>
                        </div>
                    </div>
                <?php endif; ?>
            </div>
        <?php endif; ?>

    </div>
</div>
