<?php
/*
 * Who is in the group and which instances it reaches. The controller drops
 * both lists when Security.hide_organisations_in_sharing_groups hides them
 * from this user, leaving only the member count.
 */
$sharingGroup = $sg['SharingGroup'] ?? [];
$listed = isset($sg['SharingGroupOrg']);
$members = $sg['SharingGroupOrg'] ?? [];
$servers = $sg['SharingGroupServer'] ?? [];
$roaming = !empty($sharingGroup['roaming']);

$cardHeader = function ($icon, $title, $subtitle) {
    return sprintf(
        '<div class="p-3 border-bottom"><div class="d-flex align-items-center gap-2">'
        . '<div class="rounded-2 d-flex align-items-center justify-content-center bg-primary-subtle text-primary flex-shrink-0" style="width:36px;height:36px;"><i class="%s"></i></div>'
        . '<div><div class="fw-bold lh-1">%s</div><div class="small text-muted mt-1">%s</div></div>'
        . '</div></div>',
        h($icon),
        h($title),
        h($subtitle)
    );
};
$emptyState = function ($icon, $text) {
    return '<div class="card-body text-center text-body-secondary small py-4"><i class="' . h($icon) . ' me-1 opacity-50"></i>' . h($text) . '</div>';
};
?>
<?php if (!$listed): ?>
    <div class="card mb-3 shadow-sm" data-tour="sharing-group-members">
        <?= $cardHeader(
            'misp-icon misp-icon-organisation misp-simple',
            __('Member organisations'),
            __n('%s organisation', '%s organisations', (int)($sharingGroup['org_count'] ?? 0), (int)($sharingGroup['org_count'] ?? 0))
        ) ?>
        <?= $emptyState('fas fa-eye-slash', __('The members of a sharing group are not shown on this instance.')) ?>
    </div>
<?php else: ?>
<div class="row g-3 mb-3" data-tour="sharing-group-members">
    <div class="col-lg-6">
        <div class="card h-100 shadow-sm">
            <?= $cardHeader(
                'misp-icon misp-icon-organisation misp-simple',
                __('Member organisations'),
                __n('%s organisation', '%s organisations', count($members), count($members))
            ) ?>
            <?php if (empty($members)): ?>
                <?= $emptyState('fas fa-user-slash', __('No organisation is a member yet.')) ?>
            <?php else: ?>
                <ul class="list-group list-group-flush overflow-auto" style="max-height:30rem;">
                    <?php foreach ($members as $member): ?>
                        <?php $org = $member['Organisation'] ?? []; ?>
                        <li class="list-group-item d-flex align-items-center gap-2 py-2 px-3">
                            <span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 rounded-3 border bg-body-tertiary overflow-hidden"
                                  style="width:1.75rem;height:1.75rem;">
                                <?= $this->OrgImg->getOrgLogoV2($org, 20, false) ?: '<i class="fas fa-building text-body-secondary"></i>' ?>
                            </span>
                            <a class="fw-semibold text-truncate text-decoration-none me-auto min-w-0"
                               href="<?= h($baseurl . '/organisations/view/' . ($org['id'] ?? '')) ?>"><?= h($org['name'] ?? '') ?></a>
                            <?php if (!empty($member['extend'])): ?>
                                <span class="badge rounded-pill bg-primary-subtle text-primary-emphasis border border-primary-subtle fw-normal flex-shrink-0"
                                      title="<?= h(__('Can add organisations and instances to this group')) ?>">
                                    <i class="fas fa-user-plus me-1"></i><?= __('Can extend') ?>
                                </span>
                            <?php endif; ?>
                            <span class="badge rounded-pill fw-normal flex-shrink-0 <?= !empty($org['local']) ? 'text-bg-success' : 'border bg-body text-body-secondary' ?>">
                                <i class="fas <?= !empty($org['local']) ? 'fa-house' : 'fa-globe' ?> me-1"></i><?= !empty($org['local']) ? __('Local') : __('Remote') ?>
                            </span>
                        </li>
                    <?php endforeach; ?>
                </ul>
            <?php endif; ?>
        </div>
    </div>

    <div class="col-lg-6">
        <div class="card h-100 shadow-sm">
            <?= $cardHeader(
                'fas fa-server',
                __('Instances'),
                $roaming ? __('Roaming') : __n('%s instance', '%s instances', count($servers), count($servers))
            ) ?>
            <?php if ($roaming): ?>
                <div class="card-body d-flex align-items-center gap-3">
                    <span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 rounded-3 bg-info-subtle text-info-emphasis"
                          style="width:2.25rem;height:2.25rem;"><i class="fas fa-street-view"></i></span>
                    <div class="small">
                        <div class="fw-semibold"><?= __('Roaming mode is on') ?></div>
                        <div class="text-body-secondary"><?= __('The group reaches any instance its members are on, so no instance is listed.') ?></div>
                    </div>
                </div>
            <?php elseif (empty($servers)): ?>
                <?= $emptyState('fas fa-server', __('No instance is listed yet.')) ?>
            <?php else: ?>
                <ul class="list-group list-group-flush overflow-auto" style="max-height:30rem;">
                    <?php foreach ($servers as $server): ?>
                        <?php $isLocal = (string)($server['server_id'] ?? '') === '0'; ?>
                        <li class="list-group-item d-flex align-items-center gap-2 py-2 px-3">
                            <span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 rounded-3 <?= $isLocal ? 'bg-success-subtle text-success-emphasis' : 'border bg-body-tertiary text-body-secondary' ?>"
                                  style="width:1.75rem;height:1.75rem;">
                                <i class="fas <?= $isLocal ? 'fa-house' : 'fa-server' ?>"></i>
                            </span>
                            <div class="min-w-0 me-auto lh-sm">
                                <div class="fw-semibold text-truncate"><?= h($server['Server']['name'] ?? '') ?></div>
                                <div class="small text-body-secondary font-monospace text-truncate" title="<?= h($server['Server']['url'] ?? '') ?>"><?= h($server['Server']['url'] ?? '') ?></div>
                            </div>
                            <span class="badge rounded-pill fw-normal flex-shrink-0 <?= !empty($server['all_orgs']) ? 'text-bg-success' : 'border bg-body text-body-secondary' ?>"
                                  title="<?= h(!empty($server['all_orgs'])
                                      ? __('Every organisation on that instance gets the data')
                                      : __('Only the member organisations on that instance get the data')) ?>">
                                <?= !empty($server['all_orgs']) ? __('All orgs') : __('Members only') ?>
                            </span>
                        </li>
                    <?php endforeach; ?>
                </ul>
            <?php endif; ?>
        </div>
    </div>
</div>
<?php endif; ?>
