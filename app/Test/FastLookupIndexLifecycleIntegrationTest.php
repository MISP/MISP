<?php
use PHPUnit\Framework\TestCase;

/**
 * Explicitly opt in with MISP_FASTLOOKUP_LIFECYCLE_SOCKET pointing at a disposable
 * socket-only MariaDB. Each test creates and drops its own randomly named DB.
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 */
class FastLookupIndexLifecycleIntegrationTest extends TestCase
{
    private $server;
    private $pdo;
    private $attribute;
    private $index;
    private $manager;
    private $database;
    private $socket;

    protected function setUp(): void
    {
        $this->socket = getenv('MISP_FASTLOOKUP_LIFECYCLE_SOCKET');
        if (!$this->socket || !in_array('mysql', PDO::getAvailableDrivers(), true)) {
            $this->markTestSkipped('Requires an explicitly configured disposable MariaDB socket.');
        }
        require_once __DIR__ . '/fixtures/FastLookupLifecycleStubs.php';
        require_once __DIR__ . '/../Lib/Tools/FastLookupIndexManager.php';
        $this->server = new PDO('mysql:unix_socket=' . $this->socket, 'root', '', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
        $this->database = 'fast_lookup_lifecycle_' . bin2hex(random_bytes(8));
        $this->server->exec('CREATE DATABASE ' . $this->database);
        $this->pdo = $this->connection();
        $this->pdo->exec('CREATE TABLE admin_settings (id INT AUTO_INCREMENT PRIMARY KEY, setting VARCHAR(255) NOT NULL UNIQUE, value TEXT NOT NULL) ENGINE=InnoDB');
        $this->pdo->exec('CREATE TABLE events (id INT PRIMARY KEY, published BOOLEAN NOT NULL) ENGINE=InnoDB');
        $this->pdo->exec('CREATE TABLE attributes (id INT PRIMARY KEY, event_id INT NOT NULL, type VARCHAR(255), value1 TEXT, value2 TEXT, deleted BOOLEAN NOT NULL DEFAULT FALSE) ENGINE=InnoDB');
        $this->attribute = $this->model($this->pdo);
        $this->index = new FastLookupLifecycleIndex();
        $this->manager = new FastLookupIndexManager($this->attribute, $this->index);
    }

    protected function tearDown(): void
    {
        if ($this->pdo && $this->pdo->inTransaction()) { $this->pdo->rollBack(); }
        if ($this->database) { $this->server->exec('DROP DATABASE ' . $this->database); }
    }

    private function connection()
    {
        $pdo = new PDO('mysql:unix_socket=' . $this->socket . ';dbname=' . $this->database, 'root', '', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
        $pdo->exec('SET SESSION innodb_lock_wait_timeout=1');
        return $pdo;
    }

    private function model($pdo)
    {
        $attribute = new FastLookupLifecycleAttribute();
        $attribute->db = new FastLookupLifecyclePdoSource($pdo);
        return $attribute;
    }

    private function ready()
    {
        $this->pdo->exec('INSERT INTO events VALUES (1, TRUE), (4, TRUE)');
        $this->manager->startRebuild();
        $this->assertSame('ready', $this->manager->runBatch(5)['status']);
    }

    public function testUnrelatedMutationsShareStateLockWithoutBlockingEachOther()
    {
        $this->ready();
        $second = $this->connection();
        $this->pdo->beginTransaction();
        $second->beginTransaction();
        try {
            FastLookupIndexManager::recordChange($this->attribute, '1');
            FastLookupIndexManager::recordChange($this->model($second), '4');
            $this->assertTrue($this->pdo->inTransaction());
            $this->assertTrue($second->inTransaction());
        } finally {
            $this->pdo->rollBack();
            $second->rollBack();
        }
    }

    public function testQueueCommitAndRollbackFollowSameSqlTransactionAsEvent()
    {
        $this->ready();
        $observer = $this->connection();
        $this->pdo->beginTransaction();
        $this->pdo->exec('UPDATE events SET published=FALSE WHERE id=1');
        FastLookupIndexManager::recordChange($this->attribute, '1');
        $this->assertSame(0, (int)$observer->query("SELECT COUNT(*) FROM admin_settings WHERE setting LIKE 'fastLookupIndex:dirty:%'")->fetchColumn());
        $this->pdo->rollBack();
        $this->assertSame('ready', $this->manager->status()['status']);
        $this->pdo->beginTransaction();
        $this->pdo->exec('UPDATE events SET published=FALSE WHERE id=1');
        FastLookupIndexManager::recordChange($this->attribute, '1');
        $this->pdo->commit();
        $this->assertSame('updating', $this->manager->status()['status']);
        $this->assertSame('ready', $this->manager->processPending()['status']);
        $this->assertArrayNotHasKey('1', $this->index->events);
    }

    public function testInitialDisabledMutationFencesFirstBackfillSnapshot()
    {
        Configure::$values['MISP.fast_lookup_enabled'] = false;
        $this->pdo->beginTransaction();
        $this->pdo->exec('INSERT INTO events VALUES (1, TRUE)');
        FastLookupIndexManager::recordChange($this->attribute, '1');
        $second = $this->connection();
        $other = new FastLookupIndexManager($this->model($second), $this->index);
        try {
            $other->startRebuild();
            $this->fail('A first backfill must wait for the mutation holding its activation lock.');
        } catch (PDOException $e) {
            $this->assertSame(1205, $e->errorInfo[1]);
            $this->assertTrue($this->pdo->inTransaction());
        }
        $this->pdo->commit();
        $other->startRebuild();
        $status = $other->runBatch(2);
        $this->assertSame('ready', $status['status']);
        $this->assertSame(1, $status['progress']['processed_events']);
    }
}

class FastLookupLifecyclePdoSource
{
    private $pdo;
    public $config = ['datasource' => 'Database/Mysql', 'prefix' => ''];
    public function __construct($pdo) { $this->pdo = $pdo; }
    public function getConnection() { return $this->pdo; }
    public function fullTableName($model) { return is_string($model) ? $model : $model->useTable; }
    public function name($name) { return $name; }
}
