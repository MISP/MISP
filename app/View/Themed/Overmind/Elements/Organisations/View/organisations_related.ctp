<?php
/*
 * What the Users and Sharing groups tabs hold, at a glance. Each card is only
 * drawn when the controller handed its data over, which follows the tab's own
 * gate ($orgUserSummary / $orgSharingGroups are null otherwise).
 */
$users = $orgUserSummary ?? null;
$groups = $orgSharingGroups ?? null;
if ($users === null && $groups === null) {
    return;
}
$column = ($users !== null && $groups !== null) ? 'col-lg-6' : 'col-12';

$cardHeader = function ($icon, $title, $subtitle, $tab) {
    return sprintf(
        '<div class="p-3 border-bottom"><div class="d-flex align-items-center gap-2">'
        . '<div class="rounded-2 d-flex align-items-center justify-content-center bg-primary-subtle text-primary flex-shrink-0" style="width:36px;height:36px;"><i class="%s"></i></div>'
        . '<div class="me-auto min-w-0"><div class="fw-bold lh-1">%s</div><div class="small text-muted mt-1">%s</div></div>'
        . '<a href="#tab-%s" class="btn btn-sm btn-outline-primary flex-shrink-0" data-org-tab="%s"><i class="fas fa-list me-1"></i>%s</a>'
        . '</div></div>',
        h($icon),
        h($title),
        $subtitle,
        h($tab),
        h($tab),
        h(__('Index'))
    );
};
?>
<div class="row g-3 mb-3">

    <?php if ($users !== null): ?>
        <div class="<?= $column ?>">
            <div class="card h-100 shadow-sm">
                <?php
                $active = $users['total'] - $users['disabled'];
                $subtitle = h(__n('%s account', '%s accounts', $users['total'], $users['total']));
                if ($users['disabled'] > 0) {
                    $subtitle .= ' &middot; ' . h(__n('%s disabled', '%s disabled', $users['disabled'], $users['disabled']));
                }
                ?>
                <?= $cardHeader('fas fa-users', __('Users'), $subtitle, 'users') ?>
                <?php if ($users['total'] === 0): ?>
                    <div class="card-body text-center text-body-secondary small py-4">
                        <i class="fas fa-user-slash me-1 opacity-50"></i><?= __('This organisation has no user.') ?>
                    </div>
                <?php else: ?>
                    <div class="px-3 pt-3">
                        <div class="text-body-secondary text-uppercase fw-bold mb-1" style="font-size:.7rem;"><?= __('By role') ?></div>
                        <div class="d-flex flex-wrap gap-1">
                            <?php foreach ($users['roles'] as $role): ?>
                                <?php $glyph = $this->RoleGlyph->get($role['name']); ?>
                                <span class="badge rounded-pill fw-normal d-inline-flex align-items-center gap-1"
                                      style="background:<?= h($glyph['tint']) ?>;color:<?= h($glyph['colour']) ?>;">
                                    <i class="<?= h($glyph['icon']) ?>"></i><?= h($role['name']) ?>
                                    <span class="fw-semibold"><?= h($role['count']) ?></span>
                                </span>
                            <?php endforeach; ?>
                        </div>
                    </div>
                    <div class="px-3 pt-3 text-body-secondary text-uppercase fw-bold" style="font-size:.7rem;"><?= __('Most recently active') ?></div>
                    <ul class="list-group list-group-flush">
                        <?php foreach ($users['recent'] as $user): ?>
                            <?php $glyph = $this->RoleGlyph->get($user['role_name']); ?>
                            <li class="list-group-item d-flex align-items-center gap-2 py-2 px-3<?= !empty($user['disabled']) ? ' opacity-75' : '' ?>">
                                <span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 rounded-3"
                                      style="width:1.75rem;height:1.75rem;background:<?= h($glyph['tint']) ?>;color:<?= h($glyph['colour']) ?>;"
                                      title="<?= h($user['role_name']) ?>"><i class="<?= h($glyph['icon']) ?>"></i></span>
                                <div class="min-w-0 me-auto lh-sm">
                                    <a class="d-block fw-semibold text-truncate text-decoration-none"
                                       href="<?= h($baseurl . '/admin/users/view/' . $user['id']) ?>"><?= h($user['email']) ?></a>
                                    <div class="small text-body-secondary text-truncate">
                                        <?php if (!empty($user['last_login'])): ?>
                                            <i class="fas fa-right-to-bracket me-1 opacity-50"></i><?= $this->Time->time($user['last_login']) ?>
                                        <?php else: ?>
                                            <?= __('Never logged in') ?>
                                        <?php endif; ?>
                                    </div>
                                </div>
                                <?php if (!empty($user['disabled'])): ?>
                                    <span class="badge rounded-pill border bg-body text-body-secondary fw-normal flex-shrink-0">
                                        <i class="fas fa-ban me-1"></i><?= __('Disabled') ?>
                                    </span>
                                <?php endif; ?>
                            </li>
                        <?php endforeach; ?>
                    </ul>
                    <?php if ($users['total'] > count($users['recent'])): ?>
                        <div class="card-footer bg-body small text-body-secondary py-2 px-3">
                            <?= h(__('%s of %s shown — the full list is in the Users tab.', count($users['recent']), $users['total'])) ?>
                        </div>
                    <?php endif; ?>
                <?php endif; ?>
            </div>
        </div>
    <?php endif; ?>

    <?php if ($groups !== null): ?>
        <div class="<?= $column ?>">
            <div class="card h-100 shadow-sm">
                <?= $cardHeader(
                    'misp-icon misp-icon-sharing-group misp-simple',
                    __('Sharing groups'),
                    h(__n('Creator or member of %s group', 'Creator or member of %s groups', count($groups), count($groups))),
                    'sharing_groups'
                ) ?>
                <?php if (empty($groups)): ?>
                    <div class="card-body text-center text-body-secondary small py-4">
                        <i class="fas fa-share-nodes me-1 opacity-50"></i><?= __('This organisation is in no sharing group you can see.') ?>
                    </div>
                <?php else: ?>
                    <ul class="list-group list-group-flush overflow-auto" style="max-height:24rem;">
                        <?php foreach ($groups as $group): ?>
                            <li class="list-group-item d-flex align-items-center gap-2 py-2 px-3<?= empty($group['active']) ? ' opacity-75' : '' ?>">
                                <span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 rounded-3 bg-primary-subtle text-primary"
                                      style="width:1.75rem;height:1.75rem;"><i class="misp-icon misp-icon-sharing-group misp-simple"></i></span>
                                <div class="min-w-0 me-auto lh-sm">
                                    <a class="d-block fw-semibold text-truncate text-decoration-none"
                                       href="<?= h($baseurl . '/sharing_groups/view/' . $group['id']) ?>"><?= h($group['name']) ?></a>
                                    <div class="small text-body-secondary text-truncate">
                                        <?= h(__n('%s organisation', '%s organisations', (int)$group['org_count'], (int)$group['org_count'])) ?>
                                        <?php if (!empty($group['roaming'])): ?> &middot; <?= __('Roaming') ?><?php endif; ?>
                                        <?php if (empty($group['active'])): ?> &middot; <?= __('Not selectable') ?><?php endif; ?>
                                    </div>
                                </div>
                                <?php if ($group['owner']): ?>
                                    <span class="badge rounded-pill bg-primary-subtle text-primary-emphasis border border-primary-subtle fw-normal flex-shrink-0">
                                        <i class="fas fa-crown me-1"></i><?= __('Creator') ?>
                                    </span>
                                <?php elseif ($group['extend']): ?>
                                    <span class="badge rounded-pill border bg-body text-body-secondary fw-normal flex-shrink-0" title="<?= h(__('Can add organisations and instances to this group')) ?>">
                                        <i class="fas fa-user-plus me-1"></i><?= __('Can extend') ?>
                                    </span>
                                <?php endif; ?>
                            </li>
                        <?php endforeach; ?>
                    </ul>
                <?php endif; ?>
            </div>
        </div>
    <?php endif; ?>

</div>

<script>
(function () {
    document.querySelectorAll('[data-org-tab]:not([data-org-bound])').forEach(function (link) {
        link.setAttribute('data-org-bound', '');
        link.addEventListener('click', function (event) {
            var tab = document.querySelector('.nav-link[href="#tab-' + link.dataset.orgTab + '"]');
            if (tab && window.bootstrap) {
                event.preventDefault();
                bootstrap.Tab.getOrCreateInstance(tab).show();
                window.scrollTo({ top: 0, behavior: 'smooth' });
            }
        });
    });
})();
</script>
