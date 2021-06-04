<?php

/**
 * @property Log $Log
 * @property AuditLog $AuditLog
 * @property Server $Server
 */
class LogShell extends AppShell
{
    public $uses = ['Log', 'AuditLog', 'Server'];

    public function getOptionParser()
    {
        $parser = parent::getOptionParser();
        $parser->addSubcommand('auditStatistics', [
            'help' => __('Show statistics from audit logs.'),
        ]);
        $parser->addSubcommand('statistics', [
            'help' => __('Show statistics from logs.'),
        ]);
        $parser->addSubcommand('export', [
            'help' => __('Export logs to compressed file in JSON Lines format (one JSON encoded line per entry).'),
            'parser' => array(
                'arguments' => array(
                    'file' => ['help' => __('Path to output file'), 'required' => true],
                ),
            ),
        ]);
        return $parser;
    }

    public function export()
    {
        list($path) = $this->args;

        if (file_exists($path)) {
            $this->error("File $path already exists");
        }

        $file = gzopen($path, 'wb4'); // Compression level 4 is best compromise between time and size
        if ($file === false) {
            $this->error("Could not open $path for writing");
        }

        $rows = $this->Log->query("SELECT TABLE_ROWS FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = 'logs';");
        /** @var ProgressShellHelper $progress */
        $progress = $this->helper('progress');
        $progress->init([
            'total' => $rows[0]['TABLES']['TABLE_ROWS'], // just estimate, but fast
            'width' => 50,
        ]);

        $lastId = 0;
        while (true) {
            $logs = $this->Log->find('all', [
                'conditions' => ['id >' => $lastId], // much faster than offset
                'recursive' => -1,
                'limit' => 100000,
                'order' => ['id ASC'],
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
                $lines .= json_encode($log, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n";
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
        $this->out(str_pad(__('Uncompressed size:'), 20) . CakeNumber::toReadableSize($this->AuditLog->compressionStats['bytes_uncompressed']));
        $this->out(str_pad(__('Compressed size:'), 20) . CakeNumber::toReadableSize($this->AuditLog->compressionStats['bytes_compressed']));
    }
}
