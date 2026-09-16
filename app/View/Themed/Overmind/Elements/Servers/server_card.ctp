<?php
/*
 * Bespoke card for the servers index.
 *
 * Wired in through `card_element` (see genericElementsBS5/IndexTable/index_card):
 * the scaffold keeps the .card shell — so cards_per_row, the row callables and
 * the view-switch animation still apply — and this element renders what goes
 * inside it.
 *
 * Params from index_card:
 *   row       Server, Organisation (owner), RemoteOrg, User (bound sync users)
 *   k         row index — unused here
 *   data      the scaffold data array — unused here
 *   sections  the card fields already rendered. This index declares only two:
 *             'selector' (mass-select checkbox) and 'extra' (row-action kebab),
 *             so they keep working without being restated here.
 *
 * The two async panels are filled by testConnection() / getRemoteSyncUser() from
 * mispOvermind.js, queued by the script at the bottom of Servers/index.ctp. Their
 * containers are passed explicitly because the table view is in the DOM at the
 * same time and already owns the connection_test_<id> / sync_user_test_<id> ids.
 */
$server = $row['Server'] ?? [];
if (empty($server)) {
    return;
}

$id = $server['id'];
$ownerOrg = $row['Organisation'] ?? [];
$remoteOrg = $row['RemoteOrg'] ?? [];

// Bound sync users are the User hasMany on Server.server_id.
$boundUsers = array_values(array_filter(Hash::extract($row, 'User.{n}.email')));

$connId = 'srv-conn-' . h($id);
$syncId = 'srv-sync-' . h($id);
$canAdmin = !empty($isSiteAdmin);

// A Yes/No pill. Everything in the configuration panels is a boolean column.
$flag = function ($on, $onLabel = null, $offLabel = null) {
    $on = !empty($on);
    $label = $on ? ($onLabel ?: __('Yes')) : ($offLabel ?: __('No'));
    return '<span class="srv-flag' . ($on ? ' srv-flag-on' : '') . '">'
        . h($label) . '</span>';
};

// One "label ......... value" line. $value is HTML, $label is escaped here.
$kv = function ($label, $value) {
    return '<div class="srv-kv"><span class="srv-kv-label">' . h($label) . '</span>'
        . '<span class="srv-kv-value">' . $value . '</span></div>';
};

/*
 * Panel chrome. $opts: 'accent' (text utility for the glyph), 'id', 'class',
 * 'tools' (HTML pinned to the right of the title).
 */
$panel = function ($title, $icon, $body, $opts = []) {
    $attrs = empty($opts['id']) ? '' : ' id="' . h($opts['id']) . '"';
    $class = 'srv-panel' . (empty($opts['class']) ? '' : ' ' . h($opts['class']));
    $accent = $opts['accent'] ?? 'text-primary';
    ob_start();
    ?>
    <div class="<?= $class ?>"<?= $attrs ?>>
        <div class="srv-panel-head">
            <i class="fas <?= h($icon) ?> <?= h($accent) ?>"></i>
            <span class="srv-panel-title"><?= h($title) ?></span>
            <?php if (!empty($opts['tools'])): ?>
                <span class="ms-auto d-flex align-items-center gap-1"><?= $opts['tools'] ?></span>
            <?php endif; ?>
        </div>
        <div class="srv-panel-body"><?= $body ?></div>
    </div>
    <?php
    return ob_get_clean();
};

// Re-run button shown in the head of each probe panel.
$retry = function ($probe, $title) use ($id) {
    return '<button type="button" class="btn btn-sm btn-link p-0 srv-retry"'
        . ' data-probe="' . h($probe) . '" data-server-id="' . h($id) . '"'
        . ' title="' . h($title) . '" aria-label="' . h($title) . '">'
        . '<i class="fas fa-rotate-right"></i></button>';
};

// Placeholder every probe panel starts on, replaced by the probe's own output.
$pending = '<div class="server-action-result srv-flat small">'
    . '<span class="text-muted">' . __('Waiting…') . '</span></div>';
?>

<div class="srv-card" data-server-id="<?= h($id) ?>" data-srv-state="pending">

    <div class="srv-head">
        <?php if (!empty($sections['selector'])): ?>
            <div class="srv-head-select"><?= implode('', $sections['selector']) ?></div>
        <?php endif; ?>

        <span class="srv-glyph"><i class="fas fa-server"></i></span>

        <div class="srv-head-title">
            <a href="<?= h($baseurl . '/servers/previewIndex/' . $id) ?>"
               class="srv-name text-truncate d-block"
               title="<?= h($server['name']) ?>"><?= h($server['name']) ?></a>
            <span class="srv-head-meta"><?= __('ID: %s', h($id)) ?></span>
        </div>

        <span class="srv-status" title="<?= __('Result of the connection test') ?>">
            <i class="fas fa-circle srv-status-dot"></i>
            <span class="srv-status-text"><?= __('Not tested') ?></span>
        </span>

        <?php if (!empty($sections['extra'])): ?>
            <?= implode('', $sections['extra']) ?>
        <?php endif; ?>
    </div>

    <div class="card-body">
        <div class="row g-3">

            <div class="col-12 col-md-4">
                <?= $panel(__('Connection Test'), 'fa-plug', $pending, [
                    'id' => $connId,
                    'accent' => 'text-category',
                    'class' => 'srv-probe',
                    'tools' => $retry('connection', __('Run the connection test again')),
                ]) ?>
            </div>

            <div class="col-12 col-md-4">
                <?php
                ob_start();
                echo $pending;
                if ($canAdmin) {
                    ?>
                    <?= $this->Form->postLink(
                        '',
                        $baseurl . '/servers/resetRemoteAuthKey/' . $id,
                        ['class' => 'd-none', 'id' => 'srv-reset-key-' . h($id)]
                    ) ?>
                    <button type="button" class="btn btn-sm btn-link p-0 mt-2 srv-reset-key"
                            data-server-id="<?= h($id) ?>"
                            data-server-name="<?= h($server['name']) ?>">
                        <i class="fas fa-key me-1"></i><?= __('Reset API Key') ?>
                    </button>
                    <?php
                }
                $syncBody = ob_get_clean();
                ?>
                <?= $panel(__('Sync User'), 'fa-user-gear', $syncBody, [
                    'id' => $syncId,
                    'accent' => 'text-primary',
                    'class' => 'srv-probe',
                    'tools' => $retry('sync-user', __('Fetch the remote sync user again')),
                ]) ?>
            </div>

            <div class="col-12 col-md-4">
                <?php
                $cacheValue = $flag($server['caching_enabled']);
                if (!empty($server['caching_enabled'])) {
                    $cacheValue .= '<span class="srv-kv-hint">'
                        . (empty($server['cache_timestamp'])
                            ? __('never cached')
                            : __('cached %s', $this->Time->timeAgoInWords($server['cache_timestamp'])))
                        . '</span>';
                }
                $config = $kv(__('Internal'), $flag($server['internal']))
                    . $kv(__('Publish Without Email'), $flag($server['publish_without_email']))
                    . $kv(__('Unpublish Event'), $flag($server['unpublish_event']))
                    . $kv(__('Cache'), $cacheValue)
                    . $kv(__('Skip Proxy'), $flag($server['skip_proxy']));
                ?>
                <?= $panel(__('Configuration'), 'fa-gear', $config, [
                    'accent' => 'text-secondary',
                ]) ?>
            </div>

            <div class="col-12 col-lg-6">
                <?php
                $syncLeft = $kv(__('Push'), $flag($server['push']))
                    . $kv(__('Pull'), $flag($server['pull']))
                    . $kv(__('Push Clusters'), $flag($server['push_primary_clusters']))
                    . $kv(__('Pull Clusters'), $flag($server['pull_primary_clusters']));
                $syncRight = $kv(__('Push Analyst Data'), $flag($server['push_analyst_data']))
                    . $kv(__('Pull Analyst Data'), $flag($server['pull_analyst_data']))
                    . $kv(__('Push Sightings'), $flag($server['push_sightings']));
                $syncBody = '<div class="row g-0 gx-3">'
                    . '<div class="col-12 col-sm-6">' . $syncLeft . '</div>'
                    . '<div class="col-12 col-sm-6">' . $syncRight . '</div>'
                    . '</div>';
                ?>
                <?= $panel(__('Synchronisation Options'), 'fa-arrows-rotate', $syncBody, [
                    'accent' => 'text-primary',
                ]) ?>
            </div>

            <div class="col-12 col-lg-6">
                <?php
                ob_start();
                ?>
                <div class="srv-detail">
                    <a href="<?= h($server['url']) ?>" target="_blank" rel="noreferrer noopener"
                       class="srv-url text-break"><?= h($server['url']) ?></a>
                </div>
                <?php if (!empty($remoteOrg['name'])): ?>
                    <div class="srv-detail">
                        <span class="srv-kv-label"><?= __('Host Organisation') ?></span>
                        <?php if (!empty($remoteOrg['id'])): ?>
                            <a href="<?= h($baseurl . '/organisations/view/' . $remoteOrg['id']) ?>"><?= h($remoteOrg['name']) ?></a>
                        <?php else: ?>
                            <span><?= h($remoteOrg['name']) ?></span>
                        <?php endif; ?>
                    </div>
                <?php endif; ?>
                <?php if (!empty($ownerOrg['name'])): ?>
                    <div class="srv-detail">
                        <span class="srv-kv-label"><?= __('Created by') ?></span>
                        <?php if (!empty($ownerOrg['id'])): ?>
                            <a href="<?= h($baseurl . '/organisations/view/' . $ownerOrg['id']) ?>"><?= h($ownerOrg['name']) ?></a>
                        <?php else: ?>
                            <span><?= h($ownerOrg['name']) ?></span>
                        <?php endif; ?>
                    </div>
                <?php endif; ?>
                <div class="d-flex flex-wrap gap-2 mt-2">
                    <?php if (!empty($server['cert_file'])): ?>
                        <span class="badge rounded-pill text-primary-emphasis bg-primary-subtle">
                            <i class="fas fa-certificate me-1"></i><?= __('Cert file present') ?>
                        </span>
                    <?php endif; ?>
                    <?php if (!empty($server['client_cert_file'])): ?>
                        <span class="badge rounded-pill text-primary-emphasis bg-primary-subtle">
                            <i class="fas fa-id-badge me-1"></i><?= __('Client cert present') ?>
                        </span>
                    <?php endif; ?>
                    <?php if (!empty($server['self_signed'])): ?>
                        <span class="badge rounded-pill text-warning-emphasis bg-warning-subtle">
                            <i class="fas fa-shield-halved me-1"></i><?= __('Self-signed') ?>
                        </span>
                    <?php endif; ?>
                </div>
                <?php
                $detailsBody = ob_get_clean();
                ?>
                <?= $panel(__('Server Details'), 'fa-circle-info', $detailsBody, [
                    'accent' => 'text-primary',
                ]) ?>
            </div>

            <div class="col-12">
                <?php
                if (empty($boundUsers)) {
                    $usersBody = '<span class="srv-kv-hint">' . __('None') . '</span>';
                } else {
                    $usersBody = '<div class="d-flex flex-wrap gap-2">';
                    foreach ($boundUsers as $email) {
                        $usersBody .= '<span class="srv-user-chip">' . h($email) . '</span>';
                    }
                    $usersBody .= '</div>';
                }
                ?>
                <?= $panel(__('Bound Sync Users'), 'fa-users', $usersBody, [
                    'accent' => 'text-primary',
                ]) ?>
            </div>

        </div>
    </div>

</div>
