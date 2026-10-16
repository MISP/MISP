<?php
    // The ledger figures. db_version is frozen, so the expected/actual pair
    // below can no longer differ - these are what say whether schema work is
    // outstanding. Defaulted so an older caller that does not pass them still
    // renders.
    $migrationsPending = isset($migrationsPending) ? (int)$migrationsPending : 0;
    $migrationsPendingIds = isset($migrationsPendingIds) ? (array)$migrationsPendingIds : array();
    $migrationsFailed = isset($migrationsFailed) ? (int)$migrationsFailed : 0;
    $migrationsFailedIds = isset($migrationsFailedIds) ? (array)$migrationsFailedIds : array();
    $migrationsDeferredReasons = isset($migrationsDeferredReasons) ? (array)$migrationsDeferredReasons : array();
    $migrationsApplied = isset($migrationsApplied) ? (int)$migrationsApplied : 0;

    if (($expectedDbVersion > $actualDbVersion || $migrationsPending > 0) && $updateLocked) {
        echo sprintf(
            '<div class="alert alert-warning"><strong>%s</strong> %s <br/>%s</div>',
            __('Notice'),
            __('An update is currently in progress.'),
            __('You can check the current progress %s.', sprintf('<a href="%s">%s</a>', $baseurl . '/servers/updateProgress', __('here')))
        );
    }
    foreach ((isset($warnings) ? $warnings : array()) as $warning) {
        echo sprintf('<span class="label label-warning" style="margin-left: 5px;">%s</span>', h($warning));
    }
    if ((int)$actualDbVersion >= (int)$expectedDbVersion) {
        echo sprintf('<span class="label label-success" style="margin-left: 5px;" title="%s">%s <i class="fas fa-check"></i></span>',
            __('Every legacy update has been applied. This number no longer changes; outstanding schema work is reported by the migration counters below.'),
            __('DB_version: ') . h($actualDbVersion)
        );
    } else {
        echo sprintf('<span class="label label-important" style="margin-left: 5px;" title="%s">%s <i class="fas fa-times"></i></span>',
            __('Legacy updates up to db_version %s have not all been applied. Run the updates.', h($expectedDbVersion)),
            __('DB_version: ') . h($actualDbVersion) . ' - ' . __('legacy updates pending')
        );
    }
    echo '<br/>';
    $humanReadableTime = sprintf('%smin %ssec', floor($remainingLockTime / 60), $remainingLockTime % 60);
    echo sprintf('<span class="label label-%s" title="%s" style="margin-left: 5px;">%s <i class="fas fa-%s"></i></span>',
        $updateLocked ? 'important' : 'success',
        $updateLocked ? __('Updates are locked') : __('Updates are not locked'),
        $updateLocked ? ( 
            $updateFailNumberReached ? 
                __('Updates are locked due to to many update fails') : sprintf(__('Updates unlocked in %s'), h($humanReadableTime)))
            : __('Updates are not locked'),
        $updateLocked ? 'times' : 'check'
    );
    $validDataSource = in_array($dataSource, ['Database/Mysql', 'Database/MysqlExtended', 'Database/MysqlObserverExtended', 'Database/PostgresObserverExtended'], true);
    echo sprintf('<span class="label label-%s" title="%s" style="margin-left: 5px;">%s <i class="fas fa-%s"></i></span>',
        $validDataSource ? 'success' : 'important',
        __('DataSource: ') . h($dataSource),
        __('DataSource: ') . h($dataSource),
        $validDataSource ? 'check' : 'times'
    );
    echo '<br/>';
    echo sprintf('<span class="label label-info" style="margin-left: 5px;" title="%s">%s</span>',
        __('Migrations the schema_migrations ledger records as applied'),
        __('Migrations applied: ') . h($migrationsApplied)
    );
    echo sprintf('<span class="label label-%s" style="margin-left: 5px;" title="%s">%s <i class="fas fa-%s"></i></span>',
        $migrationsPending > 0 ? 'important' : 'success',
        $migrationsPending > 0 ? __('Migrations on disk that have not been applied yet. Run the updates to apply them.') : __('Every migration on disk has been applied'),
        __('Migrations pending: ') . h($migrationsPending),
        $migrationsPending > 0 ? 'times' : 'check'
    );
    echo sprintf('<span class="label label-%s" style="margin-left: 5px;" title="%s">%s <i class="fas fa-%s"></i></span>',
        $migrationsFailed > 0 ? 'important' : 'success',
        $migrationsFailed > 0 ? __('A migration failed and the update run halted there. It is retried first on the next run.') : __('No migration has failed'),
        __('Migrations failed: ') . h($migrationsFailed),
        $migrationsFailed > 0 ? 'times' : 'check'
    );
    if ($migrationsFailed > 0) {
        echo sprintf('<div class="alert alert-error" style="margin-top: 5px;"><strong>%s</strong> %s<br/>%s</div>',
            __('Warning'),
            __('The update run halted on a failed migration. Nothing after it has been attempted; it is retried first on the next run, and the error is recorded in its ledger row.'),
            __('Failed: %s', h(implode(', ', $migrationsFailedIds)))
        );
    }
    if ($migrationsPending > 0) {
        $pendingItems = '';
        foreach ($migrationsPendingIds as $migrationId) {
            $marker = '';
            if (in_array($migrationId, $migrationsFailedIds, true)) {
                $marker = sprintf(' <span class="label label-important">%s</span>', __('failed'));
            } elseif (isset($migrationsDeferredReasons[$migrationId])) {
                $marker = sprintf(' <span class="label label-warning">%s</span><br/>%s', __('deferred'), h($migrationsDeferredReasons[$migrationId]));
            }
            $pendingItems .= sprintf('<li><code>%s</code>%s</li>', h($migrationId), $marker);
        }
        echo sprintf('<div style="margin-top: 5px;">%s <a href="%s">%s</a></div><ul>%s</ul>',
            __('Pending migrations, applied in this order by the next update run:'),
            $baseurl . '/servers/updateProgress',
            __('View update progress'),
            $pendingItems
        );
    }
