<?php
/**
 * Worker processes and checks for AttributeValueConcurrencyTest. Each worker
 * is a separate PHP process with its own database session
 * (AttributeValueInternWorker.php), so interns race the way concurrent
 * requests do.
 */

class AttributeValueWorkerPool
{
    const REPLY = '@@reply ';

    /** @var resource[] */
    private $processes = [];

    /** @var array[] stdin and stdout of each worker */
    private $pipes = [];

    /** @var string[] Partial output per worker */
    private $buffers = [];

    /** @var string[] Where each worker's stderr goes */
    private $logs = [];

    /** @var int[] Connection id or backend pid per worker */
    public $sessions = [];

    /**
     * @param array $dbConfig A datasource config; it reaches the workers over
     *   their stdin only.
     * @param string $table The dictionary table to intern into.
     * @param int $size
     */
    public function __construct(array $dbConfig, $table, $size)
    {
        $worker = __DIR__ . '/AttributeValueInternWorker.php';
        for ($i = 0; $i < $size; $i++) {
            $this->logs[$i] = tempnam(sys_get_temp_dir(), 'avworker');
            $process = proc_open(
                [PHP_BINARY, $worker],
                [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['file', $this->logs[$i], 'w']],
                $pipes
            );
            if (!is_resource($process)) {
                throw new RuntimeException('Could not start a worker.');
            }
            stream_set_blocking($pipes[1], false);
            $this->processes[$i] = $process;
            $this->pipes[$i] = $pipes;
            $this->buffers[$i] = '';
        }
        foreach (array_keys($this->processes) as $i) {
            $this->send($i, ['cmd' => 'connect', 'config' => $dbConfig, 'table' => $table]);
        }
        foreach (array_keys($this->processes) as $i) {
            $this->sessions[$i] = $this->expect($i)['session'];
        }
    }

    public function __destruct()
    {
        $this->close();
    }

    /**
     * @param int $worker
     * @param array $command
     * @return void
     */
    public function send($worker, array $command)
    {
        fwrite($this->pipes[$worker][0], json_encode($command) . "\n");
        fflush($this->pipes[$worker][0]);
    }

    /**
     * @param int $worker
     * @param float $timeout Seconds.
     * @return array|null The reply, or null when none came in time.
     */
    public function receive($worker, $timeout)
    {
        $deadline = microtime(true) + $timeout;
        while (true) {
            $newline = strpos($this->buffers[$worker], "\n");
            while ($newline !== false) {
                $line = substr($this->buffers[$worker], 0, $newline);
                $this->buffers[$worker] = substr($this->buffers[$worker], $newline + 1);
                if (strpos($line, self::REPLY) === 0) {
                    return json_decode(substr($line, strlen(self::REPLY)), true);
                }
                $newline = strpos($this->buffers[$worker], "\n");
            }
            $left = $deadline - microtime(true);
            if ($left <= 0) {
                return null;
            }
            $read = [$this->pipes[$worker][1]];
            $write = $except = null;
            if (stream_select($read, $write, $except, (int)$left, (int)(fmod($left, 1) * 1000000)) > 0) {
                $chunk = fread($this->pipes[$worker][1], 1048576);
                if ($chunk === '' && feof($this->pipes[$worker][1])) {
                    $log = (string)file_get_contents($this->logs[$worker]);
                    throw new RuntimeException("Worker $worker exited: " . substr($log, -2000));
                }
                $this->buffers[$worker] .= $chunk;
            }
        }
    }

    /**
     * A reply that must come, successful or not.
     *
     * @param int $worker
     * @param float $timeout
     * @return array
     */
    public function reply($worker, $timeout = 120.0)
    {
        $reply = $this->receive($worker, $timeout);
        if ($reply === null) {
            throw new RuntimeException("Worker $worker did not reply within $timeout s.");
        }
        return $reply;
    }

    /**
     * A reply that must come and be successful.
     *
     * @param int $worker
     * @param float $timeout
     * @return array
     */
    public function expect($worker, $timeout = 120.0)
    {
        $reply = $this->reply($worker, $timeout);
        if (empty($reply['ok'])) {
            throw new RuntimeException("Worker $worker failed: " . json_encode($reply['error']));
        }
        return $reply;
    }

    /**
     * @param int $worker
     * @param array $command
     * @return array
     */
    public function call($worker, array $command)
    {
        $this->send($worker, $command);
        return $this->expect($worker);
    }

    /**
     * Every worker interns its batch, all starting at the same moment.
     *
     * @param array $batches [worker => values]
     * @param bool $transaction Wrap each batch in its own transaction.
     * @return array [worker => reply], failures included.
     */
    public function internAll(array $batches, $transaction)
    {
        $at = microtime(true) + 0.2;
        foreach ($batches as $worker => $values) {
            $this->send($worker, [
                'cmd' => 'intern',
                'values' => $values,
                'at' => $at,
                'transaction' => $transaction,
            ]);
        }
        $replies = [];
        foreach (array_keys($batches) as $worker) {
            $replies[$worker] = $this->reply($worker);
        }
        return $replies;
    }

    /**
     * @return void
     */
    public function close()
    {
        foreach ($this->processes as $i => $process) {
            fclose($this->pipes[$i][0]);
            fclose($this->pipes[$i][1]);
            proc_terminate($process);
            proc_close($process);
            unlink($this->logs[$i]);
        }
        $this->processes = $this->pipes = $this->buffers = $this->logs = [];
    }
}

class AttributeValueConcurrency
{
    /**
     * Batches for one parallel round. Every value goes to at least two
     * workers, each worker gets its share in its own order, and the values
     * include case variants, 4-byte characters and some long enough to split
     * a chunk by bytes.
     *
     * @param string $token Keeps the values new.
     * @param int $workers At least two.
     * @param int $poolSize
     * @param int $perWorker
     * @return array ['values' => all values, 'batches' => [worker => values]]
     */
    public static function round($token, $workers, $poolSize, $perWorker)
    {
        $pool = [];
        for ($i = 0; count($pool) < $poolSize; $i++) {
            switch ($i % 5) {
                case 0:
                    $pool[] = "$token value $i";
                    $pool[] = strtoupper("$token value $i");
                    break;
                case 1:
                    $pool[] = "$token \u{1F600} $i";
                    break;
                case 2:
                    $pool[] = "$token $i " . str_repeat(chr(97 + $i % 26), 6000);
                    break;
                default:
                    $pool[] = "$token " . hash('sha256', (string)$i);
            }
        }
        $pool = array_slice($pool, 0, $poolSize);
        $batches = array_fill(0, $workers, []);
        foreach ($pool as $i => $value) {
            $first = mt_rand(0, $workers - 1);
            $batches[$first][] = $value;
            $batches[($first + 1 + mt_rand(0, $workers - 2)) % $workers][] = $value;
        }
        foreach ($batches as &$batch) {
            $extra = array_diff($pool, $batch);
            shuffle($extra);
            $batch = array_merge($batch, array_slice($extra, 0, max(0, $perWorker - count($batch))));
            shuffle($batch);
        }
        unset($batch);
        return ['values' => $pool, 'batches' => $batches];
    }

    /**
     * Parallel rounds of new, overlapping values, every worker starting each
     * round at the same moment.
     *
     * @param AttributeValueWorkerPool $pool
     * @param string $token
     * @param int $rounds
     * @param int $poolSize Distinct values per round.
     * @param int $perWorker Values per worker and round.
     * @param bool $transaction Each batch in a transaction of its own.
     * @return array ['values' => count, 'batches' => [key => values],
     *   'replies' => [key => reply]], keyed "round:worker".
     */
    public static function run(AttributeValueWorkerPool $pool, $token, $rounds, $poolSize, $perWorker, $transaction)
    {
        $run = ['values' => 0, 'batches' => [], 'replies' => []];
        for ($r = 0; $r < $rounds; $r++) {
            $round = self::round("$token r$r", count($pool->sessions), $poolSize, $perWorker);
            foreach ($pool->internAll($round['batches'], $transaction) as $worker => $reply) {
                $run['batches']["$r:$worker"] = $round['batches'][$worker];
                $run['replies']["$r:$worker"] = $reply;
            }
            $run['values'] += count($round['values']);
        }
        return $run;
    }

    /**
     * Worker 0 opens a transaction and reads, worker 1 then interns the
     * value and commits, and worker 0 interns it inside its transaction.
     *
     * @param AttributeValueWorkerPool $pool
     * @param string $value
     * @param string|null $isolation For worker 0's transaction, PostgreSQL only.
     * @return array ['committed' => worker 1's id, 'hidden' => whether a plain
     *   read in worker 0 missed it, 'reply' => worker 0's intern reply]
     */
    public static function internAfterSnapshot(AttributeValueWorkerPool $pool, $value, $isolation = null)
    {
        $pool->call(0, ['cmd' => 'begin']);
        if ($isolation) {
            $pool->call(0, ['cmd' => 'isolation', 'level' => $isolation]);
        }
        $pool->call(0, ['cmd' => 'snapshot']);
        $committed = $pool->call(1, ['cmd' => 'intern', 'values' => [$value]])['ids'][0];
        $hidden = $pool->call(0, ['cmd' => 'visible', 'values' => [$value]])['values'] === [];
        $pool->send(0, ['cmd' => 'intern', 'values' => [$value]]);
        $reply = $pool->reply(0);
        $pool->call(0, ['cmd' => empty($reply['ok']) ? 'rollback' : 'commit']);
        return ['committed' => $committed, 'hidden' => $hidden, 'reply' => $reply];
    }

    /**
     * Worker 1 interns the value inside an open transaction, worker 0 then
     * interns it too, and worker 1 ends its transaction a second later.
     *
     * @param AttributeValueWorkerPool $pool
     * @param string $value
     * @param string $end commit or rollback
     * @return array ['held' => worker 1's id, 'waited' => whether worker 0
     *   was still waiting when worker 1 ended, 'reply' => worker 0's reply]
     */
    public static function internWhileHeld(AttributeValueWorkerPool $pool, $value, $end)
    {
        $pool->call(1, ['cmd' => 'begin']);
        $held = $pool->call(1, ['cmd' => 'intern', 'values' => [$value]])['ids'][0];
        $pool->send(0, ['cmd' => 'intern', 'values' => [$value]]);
        $early = $pool->receive(0, 1.0);
        $pool->call(1, ['cmd' => $end]);
        return [
            'held' => $held,
            'waited' => $early === null,
            'reply' => $early === null ? $pool->reply(0) : $early,
        ];
    }

    /**
     * Worker 1 opens a transaction and reads, worker 0 commits the first of
     * the values, and worker 1 interns them all, which takes a locking read
     * for that one. Worker 0 then interns another value while worker 1's
     * transaction is still open.
     *
     * @param AttributeValueWorkerPool $pool
     * @param array $values
     * @param string $other
     * @return array ['late' => worker 0's id for the first value, 'held' =>
     *   worker 1's reply, 'blocked' => whether worker 0 was still waiting two
     *   seconds later, 'reply' => worker 0's reply for the other value]
     */
    public static function internBesideOpenTransaction(AttributeValueWorkerPool $pool, array $values, $other)
    {
        $pool->call(1, ['cmd' => 'begin']);
        $pool->call(1, ['cmd' => 'snapshot']);
        $late = $pool->call(0, ['cmd' => 'intern', 'values' => [$values[0]]])['ids'][0];
        $pool->send(1, ['cmd' => 'intern', 'values' => $values]);
        $held = $pool->reply(1);
        $pool->send(0, ['cmd' => 'intern', 'values' => [$other]]);
        $early = $pool->receive(0, 2.0);
        $pool->call(1, ['cmd' => 'commit']);
        return [
            'late' => $late,
            'held' => $held,
            'blocked' => $early === null,
            'reply' => $early === null ? $pool->reply(0) : $early,
        ];
    }

    /**
     * @param array $replies
     * @return array [key => error] for the batches that failed.
     */
    public static function failures(array $replies)
    {
        $failures = [];
        foreach ($replies as $key => $reply) {
            if (empty($reply['ok'])) {
                $failures[$key] = $reply['error'];
            }
        }
        return $failures;
    }

    /**
     * Everything wrong with the dictionary table after a run: each value of
     * a batch that succeeded must have exactly one row, that batch must have
     * been given the row's id, and every row must match its hash and belong
     * to such a batch. Failed batches are the caller's to judge; inside a
     * transaction their rows were rolled back.
     *
     * @param AttributeValue $model Pointed at the table under test.
     * @param array $batches [key => values], every batch of the run.
     * @param array $replies [key => reply], under the same keys.
     * @return string[]
     */
    public static function problems(AttributeValue $model, array $batches, array $replies)
    {
        $db = $model->getDataSource();
        $problems = [];
        $stored = [];
        $statement = $db->rawQuery(sprintf(
            'SELECT %s, %s, %s FROM %s',
            $db->name('id'),
            $db->name('value'),
            $db->name('hash'),
            $db->fullTableName($model->useTable)
        ));
        foreach ($statement->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $hash = is_resource($row['hash']) ? stream_get_contents($row['hash']) : (string)$row['hash'];
            if ($model->hashOf((string)$row['value']) !== $hash) {
                $problems[] = "row {$row['id']} does not match its hash";
            }
            if (isset($stored[$hash])) {
                $problems[] = "rows {$stored[$hash]} and {$row['id']} hold the same value";
            }
            $stored[$hash] = (int)$row['id'];
        }
        $statement->closeCursor();
        $wanted = [];
        foreach ($batches as $key => $batch) {
            if (empty($replies[$key]['ok'])) {
                continue;
            }
            foreach ($batch as $i => $value) {
                $hash = $model->hashOf($value);
                $wanted[$hash] = true;
                $got = $replies[$key]['ids'][$i];
                if (!isset($stored[$hash])) {
                    $problems[] = sprintf('no row for %s', json_encode(substr($value, 0, 40), JSON_INVALID_UTF8_SUBSTITUTE));
                } elseif ($got !== $stored[$hash]) {
                    $problems[] = sprintf(
                        'batch %s got id %s for %s, the row is %d',
                        $key,
                        json_encode($got),
                        json_encode(substr($value, 0, 40), JSON_INVALID_UTF8_SUBSTITUTE),
                        $stored[$hash]
                    );
                }
            }
        }
        foreach ($stored as $hash => $id) {
            if (!isset($wanted[$hash])) {
                $problems[] = "row $id belongs to no batch that succeeded";
            }
        }
        return array_values(array_unique($problems));
    }
}
