<?php
$cake = 'sudo -u www-data app/Console/cake';
$steps = [
    [
        'title' => __('Back up the database'),
        'commands' => [
            'mysqldump --single-transaction --routines --triggers --databases misp > misp-backup.sql',
        ],
        'note' => __('On PostgreSQL: %s. Replace %s with the name of your MISP database, and check that the backup restores before you go on.', '<code>pg_dump -Fc misp &gt; misp-backup.dump</code>', '<code>misp</code>'),
    ],
    [
        'title' => __('Review what will run'),
        'commands' => [$cake . ' Admin migrationStatus'],
    ],
    [
        'title' => __('Run the upgrade'),
        'commands' => [$cake . ' Admin runUpgrade'],
        'note' => __('It takes MISP offline and stops the background workers, applies every pending update, then brings both back. On a large instance this can take hours: run it in a session that survives a disconnect, such as tmux or screen. If it stops, MISP stays offline; fix the cause it reports and run it again, it carries on from there.'),
    ],
];
$guideUrl = 'https://github.com/MISP/MISP/blob/3.0_wip/docs/UPGRADE.md#attribute-values-move-to-a-value-table-misp-30';
$started = $isSiteAdmin && ($progress['running'] || $progress['stopped'] || !$isLive);
$duration = function ($seconds) {
    if ($seconds < 120) {
        return __('%s s', $seconds);
    }
    if ($seconds < 7200) {
        return __('%s min', floor($seconds / 60));
    }
    return __('%s h %s min', floor($seconds / 3600), floor($seconds % 3600 / 60));
};
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="shortcut icon" href="<?= $baseurl ?>/img/favicon.png">
    <title><?= h($title_for_layout), ' - ', h(Configure::read('MISP.title_text') ?: 'MISP') ?></title>
    <?php if ($started && ($progress['running'] || !$isLive)): ?>
    <meta http-equiv="refresh" content="15">
    <?php endif; ?>
    <style>
        :root {
            --bg: #f4f6f8;
            --card: #ffffff;
            --text: #1f2933;
            --muted: #52606d;
            --border: #d9e2ec;
            --code-bg: #f0f4f8;
            --warn-bg: #fff4e5;
            --warn-border: #f0a202;
            --warn-text: #7a4b00;
            --accent: #1b8db3;
        }
        @media (prefers-color-scheme: dark) {
            :root {
                --bg: #12171c;
                --card: #1b2229;
                --text: #e4e7eb;
                --muted: #9aa5b1;
                --border: #323f4b;
                --code-bg: #10151a;
                --warn-bg: #2b2112;
                --warn-border: #d68f00;
                --warn-text: #f7c873;
                --accent: #3fb5dc;
            }
        }
        * { box-sizing: border-box; }
        body {
            margin: 0;
            padding: 48px 16px;
            background: var(--bg);
            color: var(--text);
            font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
        }
        .card {
            max-width: 760px;
            margin: 0 auto;
            padding: 32px 36px;
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 8px;
        }
        .logo img { height: 44px; width: auto; }
        h1 { margin: 24px 0 8px; font-size: 24px; }
        .lead { margin: 0 0 24px; color: var(--muted); font-size: 16px; }
        .warning {
            margin: 0 0 28px;
            padding: 14px 18px;
            background: var(--warn-bg);
            border-left: 4px solid var(--warn-border);
            border-radius: 4px;
            color: var(--warn-text);
        }
        .warning strong { display: block; margin-bottom: 4px; font-size: 16px; }
        .warning p { margin: 0; }
        h2 { margin: 0 0 12px; font-size: 17px; }
        ol { margin: 0; padding: 0; list-style: none; counter-reset: step; }
        li { position: relative; padding: 0 0 18px 40px; counter-increment: step; }
        li::before {
            content: counter(step);
            position: absolute;
            left: 0;
            top: 0;
            width: 26px;
            height: 26px;
            border-radius: 50%;
            background: var(--accent);
            color: #fff;
            font-weight: 600;
            font-size: 13px;
            line-height: 26px;
            text-align: center;
        }
        li h3 { margin: 2px 0 6px; font-size: 15px; }
        pre {
            margin: 0;
            padding: 10px 12px;
            white-space: pre-wrap;
            overflow-wrap: anywhere;
            background: var(--code-bg);
            border: 1px solid var(--border);
            border-radius: 4px;
            font-size: 13px;
        }
        code { font-family: SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace; }
        p code { padding: 1px 4px; background: var(--code-bg); border-radius: 3px; font-size: 13px; }
        .note { margin: 6px 0 0; color: var(--muted); font-size: 14px; }
        .note.intro { margin: -6px 0 16px; }
        a { color: var(--accent); }
        .progress { margin: 0 0 28px; padding: 16px 18px; border: 1px solid var(--border); border-radius: 6px; }
        .progress h2 { margin-bottom: 10px; }
        .progress p { margin: 8px 0 0; }
        .bar { height: 8px; overflow: hidden; background: var(--code-bg); border: 1px solid var(--border); border-radius: 4px; }
        .bar span { display: block; height: 100%; background: var(--accent); }
        .progress pre { margin-top: 8px; }
        .footer { margin: 8px 0 0; padding-top: 16px; border-top: 1px solid var(--border); color: var(--muted); font-size: 14px; }
        @media (max-width: 560px) {
            body { padding: 16px; }
            .card { padding: 22px 18px; }
        }
    </style>
</head>
<body>
    <main class="card">
        <div class="logo">
            <picture>
                <source srcset="<?= $baseurl ?>/img/misp-logo-horizontal-light.png" media="(prefers-color-scheme: dark)">
                <img src="<?= $baseurl ?>/img/misp-logo-horizontal.png" alt="MISP">
            </picture>
        </div>
        <h1><?= h($title_for_layout) ?></h1>
        <?php if (!$isSiteAdmin): ?>
        <p class="lead"><?= h($message) ?></p>
        <p class="footer"><a href="<?= $baseurl ?>/users/logout"><?= __('Log out') ?></a></p>
        <?php else: ?>
        <p class="lead"><?= __('The MISP code on this instance is newer than its database. The rest of the upgrade can take hours, so it only runs from the command line. MISP stays unavailable until it is done.') ?></p>

        <?php if ($started): ?>
        <section class="progress" aria-live="polite">
            <h2><?php
                if ($progress['running']) {
                    echo __('Upgrade in progress');
                } elseif ($progress['stopped']) {
                    echo __('The upgrade stopped');
                } else {
                    echo __('MISP is offline');
                }
            ?></h2>
            <div class="bar"><span style="width: <?= $progress['total'] ? round(100 * $progress['applied'] / $progress['total'], 1) : 0 ?>%"></span></div>
            <p><?= __('%s of %s migrations applied.', $progress['applied'], $progress['total']) ?></p>
            <?php if ($progress['running'] && $progress['next']): ?>
            <p><?= __('Now applying %s: %s', '<code>' . h($progress['next']['id']) . '</code>', h($progress['next']['description'])) ?></p>
            <p class="note"><?= __('This pass started %s ago.', $duration(time() - $progress['since'])) ?></p>
            <?php if ($progress['statement']): ?>
            <p class="note"><?= __('Database: stage %s of %s, %s%% done, running for %s.', $progress['statement']['stage'], $progress['statement']['maxStage'], round($progress['statement']['percent'], 1), $duration($progress['statement']['seconds'])) ?></p>
            <?php endif; ?>
            <?php elseif ($progress['stopped']): ?>
            <p><?= __('It stopped at %s (%s). Fix the cause, then run %s again: it carries on from there.', '<code>' . h($progress['next']['id']) . '</code>', h($progress['stopped']['status']), '<code>Admin runUpgrade</code>') ?></p>
            <?php if ($progress['stopped']['error'] !== ''): ?>
            <pre><code><?= h($progress['stopped']['error']) ?></code></pre>
            <?php endif; ?>
            <?php else: ?>
            <p class="note"><?= __('No update is being applied right now. The upgrade may be between two steps.') ?></p>
            <?php endif; ?>
            <?php if ($progress['running'] || !$isLive): ?>
            <p class="note"><?= __('This page refreshes itself every 15 seconds.') ?></p>
            <?php endif; ?>
        </section>
        <?php endif; ?>

        <div class="warning" role="alert">
            <strong><?= __('This is a one-way process. Make a database backup first.') ?></strong>
            <p><?= __('Once upgraded, the database can no longer be used by the previous MISP version, and it cannot be downgraded. The only way back is to restore a backup taken before the upgrade.') ?></p>
        </div>

        <h2><?= __('Upgrade steps') ?></h2>
        <p class="note intro"><?= __('Run these from the MISP installation directory (for example %s), as the user your web server runs as. The %s explains each step and what changes; it is also in %s in that directory.', '<code>/var/www/MISP</code>', '<a href="' . h($guideUrl) . '" target="_blank" rel="noopener">' . __('upgrade guide') . '</a>', '<code>docs/UPGRADE.md</code>') ?></p>
        <ol>
            <?php foreach ($steps as $step): ?>
            <li>
                <h3><?= h($step['title']) ?></h3>
                <pre><code><?= h(implode("\n", $step['commands'])) ?></code></pre>
                <?php if (!empty($step['note'])): ?>
                <p class="note"><?= $step['note'] ?></p>
                <?php endif; ?>
            </li>
            <?php endforeach; ?>
        </ol>

        <p class="footer"><?= __('This page goes away by itself once the upgrade has finished.') ?> <a href="<?= $baseurl ?>/users/logout"><?= __('Log out') ?></a></p>
        <?php endif; ?>
    </main>
</body>
</html>
