<?php
/**
 * Confirm form for DashboardsController::invalidateUserSessions (DD-36).
 *
 * Rendered on GET (layout=false) and injected into the dashboard's own
 * side panel by user-list.module.mjs. `Form->create()` mints the
 * BetterSecurity token; the module submits the form via fetch (the
 * FormData carries the token) to POST back to the SAME endpoint, which
 * validates the token before purging the user's Redis sessions.
 *
 * There are NO data fields beyond the token, so SecurityComponent's
 * field hash stays empty and validation is trivial. The submit/cancel
 * buttons carry no `name`, so they aren't posted (they'd otherwise be
 * locked fields). Cancel is wired by the JS module (own attribute), not
 * the theme.
 *
 * Vars: $userId (int), $email (raw), $count (int), $supported (bool).
 */
$baseurl = (string)Configure::read('MISP.baseurl');
?>
<div class="misp-user-confirm">
<?php if (empty($supported)): ?>
    <p class="misp-user-confirm-text">
        <?= __('Session purging requires the PHP → Redis session engine; this instance uses a different engine, so there are no enumerable sessions to end.') ?>
    </p>
    <div class="misp-user-confirm-actions">
        <button type="button" class="misp-user-confirm-btn" data-misp-user-confirm-cancel><?= __('Close') ?></button>
    </div>
<?php else: ?>
    <?= $this->Form->create(false, array(
        'url' => $baseurl . '/dashboards/invalidateUserSessions/' . (int)$userId,
        'id' => 'misp-user-invalidate-form',
        'class' => 'misp-user-confirm-form',
    )); ?>
    <p class="misp-user-confirm-text">
        <?= sprintf(
            __('End all active sessions for %s?'),
            '<strong>' . h($email) . '</strong>'
        ) ?>
    </p>
    <p class="misp-user-confirm-sub">
        <?= sprintf(
            __('%d active session%s will be ended — the account is logged out immediately across this instance.'),
            (int)$count,
            (int)$count === 1 ? '' : 's'
        ) ?>
    </p>
    <div class="misp-user-confirm-actions">
        <button type="submit" class="misp-user-confirm-btn misp-user-confirm-btn--danger"><?= __('Invalidate sessions') ?></button>
        <button type="button" class="misp-user-confirm-btn" data-misp-user-confirm-cancel><?= __('Cancel') ?></button>
    </div>
    <?= $this->Form->end(); ?>
<?php endif; ?>
</div>
