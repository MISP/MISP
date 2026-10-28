<?php

App::uses('LogTableUpgrade', 'Migration');
App::uses('SchemaInspector', 'Migration');
App::uses('TablePreflight', 'Migration');

/**
 * Optional upgrade of the history tables to their 3.0 layout, online.
 */
class LogTablesShell extends AppShell
{
    public $uses = array();

    /** Seconds between progress lines. */
    const PROGRESS_EVERY = 10;

    public function getOptionParser()
    {
        $parser = parent::getOptionParser();
        $parser->description(__('Brings the log tables (logs, audit_logs) to the 3.0 layout: utf8mb4, 64-bit ids and the indexes the log views need. Optional, and the instance stays online; fresh installs start there.'));
        $tables = array('help' => __('Comma-separated tables to work on (default: %s).', implode(',', array_keys(LogTableUpgrade::TARGETS))));
        $parser->addSubcommand('status', array(
            'help' => __('Show where each log table stands.'),
            'parser' => array('options' => array('tables' => $tables)),
        ));
        $parser->addSubcommand('upgrade', array(
            'help' => __('Swap in an empty table at the 3.0 layout, then copy the old rows back, newest first. Run it again to resume.'),
            'parser' => array('options' => array(
                'tables' => $tables,
                'batch' => array('help' => __('Ids copied per statement.'), 'default' => 10000),
                'sleep' => array('help' => __('Milliseconds to pause between statements, to go easy on a busy server.'), 'default' => 0),
                'since' => array('help' => __('Copy back to this date only (e.g. 2024-01-01): the copy stops at the first id range that holds only older rows. finish --force then drops the rest.')),
            )),
        ));
        $parser->addSubcommand('finish', array(
            'help' => __('Drop the old tables the upgrade kept, once every row is copied.'),
            'parser' => array('options' => array(
                'tables' => $tables,
                'force' => array('help' => __('Drop them even with rows that were not copied.'), 'boolean' => true),
            )),
        ));
        return $parser;
    }

    public function status()
    {
        $upgrade = $this->upgrader();
        $free = $this->freeSpace();
        foreach ($this->tables() as $table) {
            $status = $this->call(function () use ($upgrade, $table) {
                return $upgrade->status($table);
            });
            $this->out(sprintf('%-11s %s', $table, $this->describe($status, $free)));
        }
    }

    public function upgrade()
    {
        $batch = (int)$this->param('batch');
        $pause = (int)$this->param('sleep');
        if ($batch < 1 || $pause < 0) {
            $this->error(__('--batch must be at least 1 and --sleep at least 0.'));
        }
        $since = null;
        if ($this->param('since') !== null) {
            $time = strtotime($this->param('since'));
            if ($time === false) {
                $this->error(__('--since: "%s" is not a date.', $this->param('since')));
            }
            $since = date('Y-m-d H:i:s', $time);
        }
        $upgrade = $this->upgrader();
        $this->lock($upgrade);
        foreach ($this->tables() as $table) {
            $status = $this->call(function () use ($upgrade, $table) {
                return $upgrade->status($table);
            });
            if ($status['state'] === 'current') {
                $this->out(__('%s: already at the 3.0 layout.', $table));
                continue;
            }
            if ($status['state'] === 'conflict') {
                $this->error(__('%s is not at the 3.0 layout, but %s exists. Rename or drop %s, then run this again.', $table, LogTableUpgrade::legacyName($table), LogTableUpgrade::legacyName($table)));
            }
            if ($status['state'] === 'old') {
                $this->checkSpace($table, $status['need']);
                $this->out(__('%s: swapping in an empty table at the 3.0 layout.', $table));
                $this->call(function () use ($upgrade, $table) {
                    return $upgrade->swap($table);
                });
                $this->out(__('%s: the instance now writes to the new table. The old rows follow, newest first.', $table));
                if ($table === 'logs') {
                    $this->out(__('Restart PHP-FPM or Apache when convenient: until then the web server, which keeps the old table layout in its cache, still replaces 4-byte characters such as emoji in new log entries.'));
                }
            }
            $this->copy($upgrade, $table, $batch, $pause, $since);
        }
    }

    public function finish()
    {
        $upgrade = $this->upgrader();
        $this->lock($upgrade);
        $force = (bool)$this->param('force');
        foreach ($this->tables() as $table) {
            $left = $this->call(function () use ($upgrade, $table, $force) {
                return $upgrade->finish($table, $force);
            });
            if ($left === null) {
                $this->out(__('%s: nothing to finish.', $table));
            } elseif ($left > 0) {
                $this->out(__('%s: dropped %s, with %d rows that were not copied.', $table, LogTableUpgrade::legacyName($table), $left));
            } else {
                $this->out(__('%s: dropped %s.', $table, LogTableUpgrade::legacyName($table)));
            }
        }
    }

    /**
     * @param LogTableUpgrade $upgrade
     * @param string $table
     * @param int $batch
     * @param int $pause
     * @param string|null $since
     * @return void
     */
    private function copy(LogTableUpgrade $upgrade, $table, $batch, $pause, $since)
    {
        $start = $last = microtime(true);
        $from = $this->call(function () use ($upgrade, $table) {
            return $upgrade->bounds($table);
        })['next'];
        $progress = function ($copied, array $bounds) use ($table, $start, &$last, $from) {
            $now = microtime(true);
            if ($now - $last < self::PROGRESS_EVERY) {
                return;
            }
            $last = $now;
            $idsPerSecond = ($from - $bounds['next']) / max(0.001, $now - $start);
            $this->out(__(
                '%s: %s rows copied, down to id %s of %s; about %s left.',
                $table,
                number_format($copied),
                number_format($bounds['next']),
                number_format($bounds['first']),
                $this->duration(($bounds['next'] - $bounds['first']) / max(1, $idsPerSecond))
            ));
        };
        $copied = $this->call(function () use ($upgrade, $table, $batch, $pause, $since, $progress) {
            return $upgrade->copy($table, $batch, $pause, $since, $progress);
        });
        $status = $this->call(function () use ($upgrade, $table) {
            return $upgrade->status($table);
        });
        $this->out(__('%s: %s rows copied in %s.', $table, number_format($copied), $this->duration(microtime(true) - $start)));
        if ($status['state'] === 'copied') {
            $this->out(__('%s: every row is copied. Once the log views look right, drop %s (%s) with Console/cake LogTables finish.', $table, LogTableUpgrade::legacyName($table), TablePreflight::bytes($status['bytes'])));
        } elseif ($since !== null) {
            $this->out(__('%s: the rows back to %s are copied; ids below %s stay in %s. Console/cake LogTables finish --force drops them.', $table, $since, number_format($status['next']), LogTableUpgrade::legacyName($table)));
        }
    }

    /**
     * @param float $seconds
     * @return string
     */
    private function duration($seconds)
    {
        if ($seconds < 120) {
            return __('%d s', (int)ceil($seconds));
        }
        if ($seconds < 7200) {
            return __('%d min', (int)ceil($seconds / 60));
        }
        return __('%.1f h', $seconds / 3600);
    }

    /**
     * @param array $status LogTableUpgrade::status()
     * @param array|null $free freeSpace()
     * @return string
     */
    private function describe(array $status, $free)
    {
        $legacy = LogTableUpgrade::legacyName($status['table']);
        switch ($status['state']) {
            case 'current':
                return __('3.0 layout');
            case 'old':
                $line = __('old layout, about %s rows (%s); the upgrade needs about %s free', number_format($status['rows']), TablePreflight::bytes($status['bytes']), TablePreflight::bytes($status['need']));
                return $free === null ? $line : $line . __(' (%s free in %s)', TablePreflight::bytes($free['free']), $free['path']);
            case 'copying':
                return __('3.0 layout; ids %s to %s are still in %s (Console/cake LogTables upgrade copies them)', number_format($status['first']), number_format($status['next'] - 1), $legacy);
            case 'copied':
                return __('3.0 layout; every row is copied, %s (%s) can go: Console/cake LogTables finish', $legacy, TablePreflight::bytes($status['bytes']));
            default:
                return __('not at the 3.0 layout, but %s exists', $legacy);
        }
    }

    /**
     * @param string $table
     * @param int $need Bytes.
     * @return void
     */
    private function checkSpace($table, $need)
    {
        $free = $this->freeSpace();
        if ($free === null) {
            $this->out(__('%s: the database server\'s free disk cannot be read from here; the upgrade needs about %s.', $table, TablePreflight::bytes($need)));
            return;
        }
        if ($free['free'] < $need) {
            $this->error(__('%s: the upgrade needs about %s free in %s, and %s is.', $table, TablePreflight::bytes($need), $free['path'], TablePreflight::bytes($free['free'])));
        }
    }

    /**
     * @return array|null 'path', 'free' of the database server's data
     *   directory, when it is on this host.
     */
    private function freeSpace()
    {
        $storage = (new SchemaInspector())->storage();
        return $storage === null ? null : $storage['datadir'];
    }

    /**
     * @return LogTableUpgrade
     */
    private function upgrader()
    {
        return new LogTableUpgrade(new SchemaInspector());
    }

    /**
     * @param LogTableUpgrade $upgrade
     * @return void
     */
    private function lock(LogTableUpgrade $upgrade)
    {
        if (!$upgrade->lock()) {
            $this->error(__('Another LogTables run is working on the log tables.'));
        }
    }

    /**
     * @return array
     */
    private function tables()
    {
        $tables = $this->param('tables');
        $tables = $tables === null ? array_keys(LogTableUpgrade::TARGETS) : array_filter(array_map('trim', explode(',', $tables)));
        foreach ($tables as $table) {
            if (!isset(LogTableUpgrade::TARGETS[$table])) {
                $this->error(__('Unknown log table "%s"; the tables are %s.', $table, implode(', ', array_keys(LogTableUpgrade::TARGETS))));
            }
        }
        return $tables;
    }

    /**
     * @param callable $step
     * @return mixed
     */
    private function call($step)
    {
        try {
            return $step();
        } catch (Exception $e) {
            $this->error($e->getMessage());
        }
    }
}
