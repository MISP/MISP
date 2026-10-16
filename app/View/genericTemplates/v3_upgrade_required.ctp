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
        'title' => __('Take MISP offline'),
        'commands' => [$cake . ' Admin live 0'],
    ],
    [
        'title' => __('Review what will run'),
        'commands' => [$cake . ' Admin migrationStatus'],
    ],
    [
        'title' => __('Run the upgrade'),
        'commands' => [$cake . ' Admin runUpdates'],
        'note' => __('On a large instance this can take hours. Run it in a session that survives a disconnect, such as tmux or screen, and let it finish.'),
    ],
    [
        'title' => __('Bring MISP back online'),
        'commands' => [$cake . ' Admin live 1'],
    ],
];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="shortcut icon" href="<?= $baseurl ?>/img/favicon.png">
    <title><?= h($title_for_layout), ' - ', h(Configure::read('MISP.title_text') ?: 'MISP') ?></title>
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
        <p class="lead"><?= __('The MISP code on this instance is newer than its database. The rest of the upgrade can take hours, so it only runs from the command line, never from the web interface. MISP stays unavailable until it is done.') ?></p>

        <div class="warning" role="alert">
            <strong><?= __('This is a one-way process. Make a database backup first.') ?></strong>
            <p><?= __('Once upgraded, the database can no longer be used by the previous MISP version, and it cannot be downgraded. The only way back is to restore a backup taken before the upgrade.') ?></p>
        </div>

        <h2><?= __('Upgrade steps') ?></h2>
        <p class="note intro"><?= __('Run these from the MISP installation directory (for example %s), as the user your web server runs as.', '<code>/var/www/MISP</code>') ?></p>
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
