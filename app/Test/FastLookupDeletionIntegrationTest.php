<?php
use PHPUnit\Framework\TestCase;

/**
 * Real Cake delete/callback/transaction behavior on disposable MariaDB only.
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 */
class FastLookupDeletionIntegrationTest extends TestCase
{
    private $server;
    private $pdo;
    private $observer;
    private $db;
    private $database;

    protected function setUp(): void
    {
        $socket = getenv('MISP_FASTLOOKUP_LIFECYCLE_SOCKET');
        $cake = getenv('MISP_FASTLOOKUP_CAKE_DIR') ?: dirname(__DIR__) . '/Lib/cakephp/lib/Cake';
        if (!$socket || !in_array('mysql', PDO::getAvailableDrivers(), true) || !is_file($cake . '/Model/Model.php')) {
            $this->markTestSkipped('Requires disposable MariaDB and the pinned CakePHP checkout.');
        }
        putenv('MISP_FASTLOOKUP_CAKE_DIR=' . $cake);
        require_once __DIR__ . '/fixtures/FastLookupDeletionCakeBootstrap.php';
        $this->server = new PDO('mysql:unix_socket=' . $socket, 'root', '', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
        $this->database = 'fast_lookup_deletion_' . bin2hex(random_bytes(8));
        $this->server->exec('CREATE DATABASE ' . $this->database);
        ConnectionManager::create('default', ['datasource' => 'Database/MysqlExtended', 'unix_socket' => $socket,
            'login' => 'root', 'password' => '', 'database' => $this->database,
            'prefix' => '', 'encoding' => 'utf8mb4', 'persistent' => false]);
        $this->db = ConnectionManager::getDataSource('default');
        $this->pdo = $this->db->getConnection();
        $this->observer = new PDO('mysql:unix_socket=' . $socket . ';dbname=' . $this->database, 'root', '', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
        $this->pdo->exec('CREATE TABLE admin_settings (id INT AUTO_INCREMENT PRIMARY KEY, setting VARCHAR(255) NOT NULL UNIQUE, value TEXT NOT NULL) ENGINE=InnoDB');
        $this->pdo->prepare('INSERT INTO admin_settings (setting, value) VALUES (?, ?)')->execute([FastLookupIndexManager::STATE_SETTING, '{"generation":"existing-index"}']);
        $this->pdo->exec('CREATE TABLE events (id INT PRIMARY KEY, published BOOLEAN, attribute_count INT) ENGINE=InnoDB');
        $this->pdo->exec('INSERT INTO events VALUES (1, TRUE, 1)');
        $this->pdo->exec('CREATE TABLE attributes (id INT PRIMARY KEY, event_id INT) ENGINE=InnoDB');
        $this->pdo->exec('INSERT INTO attributes VALUES (10, 1)');
        $this->pdo->exec('CREATE TABLE deletion_audit (id INT AUTO_INCREMENT PRIMARY KEY, event_id INT) ENGINE=InnoDB');
        foreach (['shadow_attributes', 'event_tags', 'attribute_tags', 'threads', 'sightings', 'event_delegations', 'objects', 'object_references', 'event_reports'] as $table) {
            $this->pdo->exec("CREATE TABLE $table (id INT PRIMARY KEY, event_id INT) ENGINE=InnoDB");
        }
        ClassRegistry::addObject('Thread', new Model(['name' => 'Thread', 'table' => 'threads', 'ds' => 'default']));
    }

    protected function tearDown(): void
    {
        if ($this->pdo && $this->pdo->inTransaction()) { $this->pdo->rollBack(); }
        if (class_exists('FastLookupIndexManager', false)) {
            // Avoid dispatching a production shutdown job after dropping fixtures.
            $models = new ReflectionProperty(FastLookupIndexManager::class, 'dispatchModels');
            $models->setAccessible(true);
            $models->setValue(null, []);
        }
        if ($this->database) { $this->server->exec('DROP DATABASE ' . $this->database); }
    }

    public static function deletionModes(): array
    {
        return [['attribute'], ['event'], ['quick']];
    }

    private function model($mode)
    {
        return $mode === 'attribute' ? new FastLookupDeletionAttribute() : new FastLookupDeletionEvent();
    }

    private function delete($model, $mode)
    {
        return $mode === 'quick' ? $model->quickDelete(['Event' => ['id' => 1]]) : $model->delete($mode === 'attribute' ? 10 : 1, false);
    }

    private function rejectDirtyInsert(): void
    {
        $this->pdo->exec("CREATE TRIGGER reject_dirty BEFORE INSERT ON admin_settings FOR EACH ROW BEGIN IF NEW.setting LIKE 'fastLookupIndex:dirty:%' THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'deliberate dirty marker failure'; END IF; END");
    }

    /** @dataProvider deletionModes */
    public function testFailedMarkerRollsBackDeletionAndNestedCallbackSave($mode): void
    {
        $this->rejectDirtyInsert();
        $model = $this->model($mode);
        $model->nestedSave = true;
        try {
            $this->delete($model, $mode);
            $this->fail('The SQL trigger must reject the dirty marker.');
        } catch (PDOException $e) {
            $this->assertStringContainsString('deliberate dirty marker failure', $e->getMessage());
        }
        $this->assertSame(1, (int)$this->observer->query('SELECT COUNT(*) FROM events')->fetchColumn());
        $this->assertSame(1, (int)$this->observer->query('SELECT COUNT(*) FROM attributes')->fetchColumn());
        $this->assertSame(0, (int)$this->observer->query('SELECT COUNT(*) FROM deletion_audit')->fetchColumn());
        $this->assertFalse($this->pdo->inTransaction());
        $this->assertTrue($this->db->begin(), 'Cake transaction bookkeeping must remain usable.');
        $this->assertTrue($this->db->rollback());
    }

    /** @dataProvider deletionModes */
    public function testSuccessfulDeletionCommitsMarkerAndNestedCallbackSave($mode): void
    {
        $model = $this->model($mode);
        $model->nestedSave = true;
        $this->assertTrue($this->delete($model, $mode));
        $table = $mode === 'attribute' ? 'attributes' : 'events';
        $this->assertSame(0, (int)$this->observer->query("SELECT COUNT(*) FROM $table")->fetchColumn());
        $this->assertSame(1, (int)$this->observer->query("SELECT COUNT(*) FROM admin_settings WHERE setting LIKE 'fastLookupIndex:dirty:%'")->fetchColumn());
        $this->assertSame(1, (int)$this->observer->query('SELECT COUNT(*) FROM deletion_audit')->fetchColumn());
        $this->assertFalse($this->pdo->inTransaction());
    }

    /** @dataProvider deletionModes */
    public function testCallerCakeTransactionRetainsDeletionMarkerAndNestedSave($mode): void
    {
        $model = $this->model($mode);
        $model->nestedSave = true;
        $this->db->begin();
        $this->assertTrue($this->delete($model, $mode));
        $this->assertTrue($this->pdo->inTransaction());
        $this->assertSame(0, (int)$this->observer->query("SELECT COUNT(*) FROM admin_settings WHERE setting LIKE 'fastLookupIndex:dirty:%'")->fetchColumn());
        $this->db->rollback();
        $this->assertSame(1, (int)$this->observer->query('SELECT COUNT(*) FROM events')->fetchColumn());
        $this->assertSame(1, (int)$this->observer->query('SELECT COUNT(*) FROM attributes')->fetchColumn());
        $this->assertSame(0, (int)$this->observer->query('SELECT COUNT(*) FROM deletion_audit')->fetchColumn());
    }

    /** @dataProvider deletionModes */
    public function testCallerPdoTransactionIsNotCommittedOrRolledBackOnFailure($mode): void
    {
        $this->rejectDirtyInsert();
        $this->pdo->beginTransaction();
        try {
            $this->delete($this->model($mode), $mode);
            $this->fail('The SQL trigger must reject the dirty marker.');
        } catch (PDOException $e) {
            $this->assertStringContainsString('deliberate dirty marker failure', $e->getMessage());
        }
        $this->assertTrue($this->pdo->inTransaction());
        $this->pdo->rollBack();
        $this->assertSame(1, (int)$this->observer->query('SELECT COUNT(*) FROM events')->fetchColumn());
        $this->assertSame(1, (int)$this->observer->query('SELECT COUNT(*) FROM attributes')->fetchColumn());
    }

    public function testHardDeletingSoftDeletedAttributeKeepsAttributeCount(): void
    {
        // A soft delete already decremented attribute_count; the hard delete by
        // ID must still record the IOC index change without decrementing again.
        $this->pdo->exec("ALTER TABLE attributes ADD type VARCHAR(100) NOT NULL DEFAULT 'ip-src', ADD value1 TEXT NOT NULL DEFAULT '192.0.2.1', ADD value2 TEXT NOT NULL DEFAULT '', ADD deleted BOOLEAN NOT NULL DEFAULT FALSE");
        $this->pdo->exec('UPDATE attributes SET deleted = TRUE WHERE id = 10');
        $this->pdo->exec('UPDATE events SET attribute_count = 0 WHERE id = 1');
        $this->pdo->exec('INSERT INTO attributes (id, event_id) VALUES (11, 1)');
        $this->pdo->exec('UPDATE events SET attribute_count = 1 WHERE id = 1');
        $this->assertTrue((new FastLookupRealCallbackAttribute())->delete(10, false));
        $this->assertSame(1, (int)$this->observer->query('SELECT attribute_count FROM events WHERE id = 1')->fetchColumn());
        $this->assertSame(1, (int)$this->observer->query("SELECT COUNT(*) FROM admin_settings WHERE setting LIKE 'fastLookupIndex:dirty:%1'")->fetchColumn());
        $this->assertSame(1, (int)$this->observer->query('SELECT COUNT(*) FROM attributes')->fetchColumn());
    }

    public function testQuickDeleteVetoRollsBackPreviouslyDeletedChildren(): void
    {
        $model = $this->model('quick');
        $model->veto = true;
        $this->assertFalse($this->delete($model, 'quick'));
        $this->assertSame(1, (int)$this->observer->query('SELECT COUNT(*) FROM attributes')->fetchColumn());
        $this->assertSame(1, (int)$this->observer->query('SELECT COUNT(*) FROM events')->fetchColumn());
        $this->assertFalse($this->pdo->inTransaction());
    }
}
