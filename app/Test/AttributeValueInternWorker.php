<?php
/**
 * One database session for AttributeValueConcurrencyTest, driven over
 * stdin/stdout by AttributeValueWorkerPool: one JSON command per line in, one
 * JSON reply per line out. Replies carry a prefix so that anything else the
 * application prints cannot be mistaken for one.
 *
 * Not a test; it is started by the pool, never by PHPUnit.
 */

require __DIR__ . '/OracleBootstrap.php';
App::uses('ConnectionManager', 'Model');
App::uses('ClassRegistry', 'Utility');

const ATTRIBUTE_VALUE_WORKER_REPLY = '@@reply ';

/**
 * @param array $reply
 * @return void
 */
function attributeValueWorkerReply(array $reply)
{
    fwrite(STDOUT, ATTRIBUTE_VALUE_WORKER_REPLY . json_encode($reply, JSON_INVALID_UTF8_SUBSTITUTE) . "\n");
    fflush(STDOUT);
}

/**
 * @param Throwable $e
 * @return array
 */
function attributeValueWorkerError(Throwable $e)
{
    $error = ['class' => get_class($e), 'message' => $e->getMessage(), 'sqlstate' => null, 'code' => null];
    if ($e instanceof PDOException && is_array($e->errorInfo)) {
        $error['sqlstate'] = $e->errorInfo[0];
        $error['code'] = $e->errorInfo[1];
    }
    return $error;
}

/** @var AttributeValue|null $model */
$model = null;
/** @var DboSource|null $db */
$db = null;

while (($line = fgets(STDIN)) !== false) {
    $command = json_decode($line, true);
    if (!is_array($command) || !isset($command['cmd'])) {
        attributeValueWorkerReply(['ok' => false, 'error' => ['message' => 'Unreadable command.']]);
        continue;
    }
    $reply = ['ok' => true];
    try {
        switch ($command['cmd']) {
            case 'connect':
                // The scratch table is newer than any cached table list
                ConnectionManager::create('attribute_value_worker', $command['config'])->cacheSources = false;
                $model = ClassRegistry::init([
                    'class' => 'AttributeValue',
                    'table' => $command['table'],
                    'ds' => 'attribute_value_worker',
                ]);
                $db = $model->getDataSource();
                $sql = $db instanceof Mysql ? 'SELECT CONNECTION_ID()' : 'SELECT pg_backend_pid()';
                $reply['session'] = (int)$db->getConnection()->query($sql)->fetchColumn();
                break;
            case 'begin':
                $db->begin();
                break;
            case 'commit':
                $db->commit();
                break;
            case 'rollback':
                $db->rollback();
                break;
            case 'isolation':
                // Only before the first statement of a transaction
                $db->rawQuery('SET TRANSACTION ISOLATION LEVEL ' . $command['level']);
                break;
            case 'snapshot':
                // A plain read, which fixes the snapshot of a REPEATABLE READ transaction
                $statement = $db->rawQuery('SELECT COUNT(*) FROM ' . $db->fullTableName($model->useTable));
                $reply['rows'] = (int)$statement->fetchColumn();
                $statement->closeCursor();
                break;
            case 'visible':
                // Which values a plain read sees, without a locking read
                $literals = [];
                foreach ($command['values'] as $value) {
                    $literals[] = $model->getSqlDialect()->binaryLiteral($model->hashOf($value));
                }
                $statement = $db->rawQuery(sprintf(
                    'SELECT %s FROM %s WHERE %s IN (%s)',
                    $db->name('value'),
                    $db->fullTableName($model->useTable),
                    $db->name('hash'),
                    implode(', ', $literals)
                ));
                $reply['values'] = $statement->fetchAll(PDO::FETCH_COLUMN);
                $statement->closeCursor();
                break;
            case 'intern':
                if (!empty($command['at'])) {
                    $wait = $command['at'] - microtime(true);
                    if ($wait > 0) {
                        usleep((int)($wait * 1000000));
                    }
                }
                $transaction = !empty($command['transaction']);
                $start = microtime(true);
                try {
                    if ($transaction) {
                        $db->begin();
                    }
                    $ids = $model->internMany($command['values']);
                    if ($transaction) {
                        $db->commit();
                    }
                } catch (Throwable $e) {
                    if ($transaction) {
                        $db->rollback();
                    }
                    throw $e;
                } finally {
                    $reply['seconds'] = microtime(true) - $start;
                }
                $reply['ids'] = [];
                foreach ($command['values'] as $value) {
                    $reply['ids'][] = $ids[$value];
                }
                break;
            case 'exit':
                attributeValueWorkerReply($reply);
                exit(0);
            default:
                throw new InvalidArgumentException('Unknown command ' . $command['cmd']);
        }
    } catch (Throwable $e) {
        $reply = ['ok' => false, 'error' => attributeValueWorkerError($e)] + $reply;
    }
    attributeValueWorkerReply($reply);
}
