<?php

/**
 * @property Log $Log
 * @property AuditLog $AuditLog
 * @property AccessLog $AccessLog
 * @property Server $Server
 */
class LogShell extends AppShell
{
    public $uses = ['Log', 'AuditLog', 'AccessLog', 'Server'];

    public function getOptionParser()
    {
        $parser = parent::getOptionParser();
        $parser->addSubcommand('auditStatistics', [
            'help' => __('Show statistics for audit logs.'),
        ]);
        $parser->addSubcommand('accessStatistics', [
            'help' => __('Show statistics for access logs.'),
        ]);
        $parser->addSubcommand('statistics', [
            'help' => __('Show statistics for application logs.'),
        ]);
        $parser->addSubcommand('export', [
            'help' => __('Export application logs to compressed file in JSON Lines format (one JSON encoded line per entry).'),
            'parser' => [
                'arguments' => [
                    'file' => ['help' => __('Path to output file'), 'required' => true],
                ],
                'options' => [
                    'without-changes' => ['boolean' => true, 'help' => __('Do not include add, edit or delete actions.')],
                ],
            ],
        ]);
        $parser->addSubcommand('recompress', [
            'help' => __('Recompress compressed data in logs.'),
        ]);
        $parser->addSubcommand('accessLogRetention', [
            'help' => __('Delete logs that are older than specified duration.'),
            'parser' => array(
                'arguments' => array(
                    'duration' => ['help' => __('Duration in days'), 'required' => true],
                ),
            ),
        ]);
        return $parser;
    }

    public function export()
    {
        list($path) = $this->args;
        $withoutChanges = $this->param('without-changes');

        if (file_exists($path)) {
            $this->error("File $path already exists");
        }

        $file = gzopen($path, 'wb4'); // Compression level 4 is best compromise between time and size
        if ($file === false) {
            $this->error("Could not open $path for writing");
        }

        /** @var ProgressShellHelper $progress */
        $progress = $this->helper('progress');
        $progress->init([
            'total' => $this->Log->tableRows(), // just estimate, but fast
            'width' => 50,
        ]);

        $lastId = 0;
        while (true) {
            $conditions = ['Log.id >' => $lastId]; // much faster than offset
            if ($withoutChanges) {
                $conditions['NOT'] = ['Log.action' => ['add', 'edit', 'delete']];
            }
            $logs = $this->Log->find('all', [
                'conditions' => $conditions,
                'recursive' => -1,
                'limit' => 100000,
                'order' => ['Log.id ASC'],
            ]);
            if (empty($logs)) {
                break;
            }
            $lines = '';
            foreach ($logs as $log) {
                $log = $log['Log'];
                foreach (['id', 'model_id', 'user_id'] as $field) {
                    $log[$field] = (int)$log[$field]; // Convert to int to save space
                }
                if (empty($log['description'])) {
                    unset($log['description']);
                }
                if (empty($log['ip'])) {
                    unset($log['ip']);
                }
                $log['created'] = strtotime($log['created']); // to save space
                if ($log['id'] > $lastId) {
                    $lastId = $log['id'];
                }
                $lines .= JsonTool::encode($log) . "\n";
            }
            if (gzwrite($file, $lines) === false) {
                $this->error("Could not write data to $path");
            }
            $progress->increment(count($logs));
            $progress->draw();
        }
        gzclose($file);
        $this->out('Done');
    }

    public function statistics()
    {
        $count = $this->Log->find('count');
        $first = $this->Log->find('first', [
            'recursive' => -1,
            'fields' => ['created'],
            'order' => ['id ASC'],
        ]);
        $last = $this->Log->find('first', [
            'recursive' => -1,
            'fields' => ['created'],
            'order' => ['id DESC'],
        ]);

        $this->out(str_pad(__('Count:'), 20) . $count);
        $this->out(str_pad(__('First:'), 20) . $first['Log']['created']);
        $this->out(str_pad(__('Last:'), 20) . $last['Log']['created']);

        $usage = $this->Server->dbSpaceUsage()['logs'];
        $this->out(str_pad(__('Data size:'), 20) . CakeNumber::toReadableSize($usage['data_in_bytes']));
        $this->out(str_pad(__('Index size:'), 20) . CakeNumber::toReadableSize($usage['index_in_bytes']));
        $this->out(str_pad(__('Reclaimable size:'), 20) . CakeNumber::toReadableSize($usage['reclaimable_in_bytes']), 2);
    }

    public function auditStatistics()
    {
        $count = $this->AuditLog->find('count');
        $first = $this->AuditLog->find('first', [
            'recursive' => -1,
            'fields' => ['created'],
            'order' => ['id ASC'],
        ]);
        $last = $this->AuditLog->find('first', [
            'recursive' => -1,
            'fields' => ['created'],
            'order' => ['id DESC'],
        ]);

        $this->out(str_pad(__('Count:'), 20) . $count);
        $this->out(str_pad(__('First:'), 20) . $first['AuditLog']['created']);
        $this->out(str_pad(__('Last:'), 20) . $last['AuditLog']['created']);

        $usage = $this->Server->dbSpaceUsage()['audit_logs'];
        $this->out(str_pad(__('Data size:'), 20) . CakeNumber::toReadableSize($usage['data_in_bytes']));
        $this->out(str_pad(__('Index size:'), 20) . CakeNumber::toReadableSize($usage['index_in_bytes']));
        $this->out(str_pad(__('Reclaimable size:'), 20) . CakeNumber::toReadableSize($usage['reclaimable_in_bytes']), 2);

        // Just to fetch compressionStats
        $this->AuditLog->find('column', [
            'fields' => ['change'],
        ]);

        $this->out('Change field:');
        $this->out('-------------');
        $this->out(str_pad(__('Compressed items:'), 20) . $this->AuditLog->compressionStats['compressed']);
        $this->out(str_pad(__('Total size:'), 20) . CakeNumber::toReadableSize($this->AuditLog->compressionStats['bytes_total']));
        $this->out(str_pad(__('Uncompressed size:'), 20) . CakeNumber::toReadableSize($this->AuditLog->compressionStats['bytes_uncompressed']));
        $this->out(str_pad(__('Compressed size:'), 20) . CakeNumber::toReadableSize($this->AuditLog->compressionStats['bytes_compressed']));
    }

    public function accessStatistics()
    {
        $count = $this->AccessLog->find('count');
        $first = $this->AccessLog->find('first', [
            'recursive' => -1,
            'fields' => ['created'],
            'order' => ['id ASC'],
        ]);
        $last = $this->AccessLog->find('first', [
            'recursive' => -1,
            'fields' => ['created'],
            'order' => ['id DESC'],
        ]);

        $this->out(str_pad(__('Count:'), 20) . $count);
        $this->out(str_pad(__('First:'), 20) . $first['AccessLog']['created']);
        $this->out(str_pad(__('Last:'), 20) . $last['AccessLog']['created']);

        $usage = $this->Server->dbSpaceUsage()['access_logs'];
        $this->out(str_pad(__('Data size:'), 20) . CakeNumber::toReadableSize($usage['data_in_bytes']));
        $this->out(str_pad(__('Index size:'), 20) . CakeNumber::toReadableSize($usage['index_in_bytes']));
        $this->out(str_pad(__('Reclaimable size:'), 20) . CakeNumber::toReadableSize($usage['reclaimable_in_bytes']), 2);
    }

    public function recompress()
    {
        $this->AuditLog->recompress();
    }

    public function accessLogRetention()
    {
        list($duration) = $this->args;
        if ($duration <= 0 || !is_numeric($duration)) {
            $this->error("Invalid duration specified.");
        }
        $duration = new DateTime("-$duration days");
        $deleted = $this->AccessLog->deleteOldLogs($duration);
        $this->out(__n("Deleted %s entry", "Deleted %s entries", $deleted, $deleted));
    }
}
