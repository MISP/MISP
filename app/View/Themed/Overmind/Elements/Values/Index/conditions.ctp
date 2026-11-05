<?php
/**
 * The analyst profile in force, as a menu at the end of the bar: whose
 * thresholds decide this reader's assessments, and the method note saying
 * what an assessment is.
 *
 * The name says which document, the revision which version of it — a
 * band that moved overnight moved because the value did or because the
 * profile did — and the scope says whose pages an edit would move.
 *
 * **The link goes where the reader may actually go.** `editable` is
 * `AnalystProfilesController::edit()`'s own predicate, so an analyst on
 * their organisation's profile without `perm_admin` is offered the page
 * that shows the thresholds instead of a link that 403s.
 *
 * **No profile in force is a state, not a failure.** A site admin can
 * disable the default, and every assessment then carries a lean and no
 * signal strength; said plainly, it cannot be mistaken for a broken
 * engine.
 *
 * @var array{id: int|null, name: string, scope: string,
 *            revision: int, editable: bool}|null $inForce
 */
$shows = $showsAssessment ?? true;
$scopes = array(
    'user' => __('Your personal analyst profile.'),
    'org' => __('Your organisation\'s analyst profile.'),
    'shared' => __('A shared analyst profile.'),
);
$link = null;
if ($inForce !== null && $inForce['id'] !== null) {
    $link = $this->Html->link(
        $shows
            ? ($inForce['editable'] ? __('Edit thresholds') : __('View thresholds'))
            : ($inForce['editable'] ? __('Edit profile') : __('View profile')),
        array(
            'controller' => 'analystProfiles',
            'action' => $inForce['editable'] ? 'edit' : 'view',
            $inForce['id'],
            '?' => $shows ? array() : array('section' => 'context'),
        ),
        array('class' => 'vi-condlink')
    );
}
if ($inForce === null) {
    $button = __('No analyst profile');
} elseif (!$shows) {
    $button = __('Assessment off');
} else {
    $button = $inForce['name'];
}
?>
<div class="dropdown vi-cond-menu">
    <button type="button" class="ifp-fbtn<?= $inForce !== null && $shows ? ' is-set' : '' ?>"
            data-bs-toggle="dropdown" data-bs-auto-close="outside" aria-expanded="false"
            title="<?= h(__('The analyst profile deciding the assessments')) ?>">
        <i class="fas fa-scale-balanced" aria-hidden="true"></i>
        <span class="vi-cond-name"><?= h($button) ?></span>
        <i class="fas fa-chevron-down ifp-caret" aria-hidden="true"></i>
    </button>
    <div class="dropdown-menu dropdown-menu-end vi-cond">
<?php if ($inForce === null): ?>
        <p><?= h(__(
            'No analyst profile is active, so assessments show a lean but'
            . ' no signal strength until a site admin enables one.'
        )) ?></p>
<?php else: ?>
        <p class="vi-cond__name">
            <b><?= h($inForce['name']) ?></b>
            <span class="vi-rev"><?= h(sprintf(__('rev %d'), $inForce['revision'])) ?></span>
        </p>
        <p><?php if (!$shows): ?><?= h(__(
            'It switches the assessment off, so values are listed without'
            . ' a lean, signal strength or relevance.'
        )) ?><?php elseif (isset($scopes[$inForce['scope']])): ?><?= h($scopes[$inForce['scope']]) ?><?php else: ?><?= h(__(
            'The instance default. Only a site admin can change it.'
        )) ?><?php endif; ?></p>
<?php endif; ?>
<?php if ($link !== null || $shows): ?>
        <div class="vi-cond__links">
<?php   if ($link !== null): ?>
            <?= $link ?>
<?php   endif; ?>
<?php   if ($shows): ?>
            <?= $this->element('Values/Index/method') ?>
<?php   endif; ?>
        </div>
<?php endif; ?>
    </div>
</div>
