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
    private $attributeRows = 1;
    private $quickDeleteSurvivors;

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
        $this->pdo->exec("CREATE TABLE attributes (id INT PRIMARY KEY, event_id INT, type VARCHAR(100) NOT NULL DEFAULT 'ip-src') ENGINE=InnoDB");
        $this->pdo->exec('INSERT INTO attributes (id, event_id) VALUES (10, 1)');
        $this->pdo->exec('CREATE TABLE deletion_audit (id INT AUTO_INCREMENT PRIMARY KEY, event_id INT) ENGINE=InnoDB');
        foreach (['event_tags', 'attribute_tags', 'threads', 'sightings', 'event_delegations', 'objects', 'object_references', 'event_reports', 'event_graph'] as $table) {
            $this->pdo->exec("CREATE TABLE $table (id INT PRIMARY KEY, event_id INT) ENGINE=InnoDB");
        }
        $this->pdo->exec('CREATE TABLE shadow_attributes (id INT PRIMARY KEY, event_id INT, type VARCHAR(100) NOT NULL) ENGINE=InnoDB');
        $this->pdo->exec('CREATE TABLE shadow_attribute_correlations (id INT PRIMARY KEY, event_id INT, 1_event_id INT) ENGINE=InnoDB');
        $this->pdo->exec('CREATE TABLE event_report_tags (id INT AUTO_INCREMENT PRIMARY KEY, event_report_id INT NOT NULL) ENGINE=InnoDB');
        $this->pdo->exec('CREATE TABLE attachment_scans (id INT AUTO_INCREMENT PRIMARY KEY, type VARCHAR(40) NOT NULL, attribute_id INT NOT NULL) ENGINE=InnoDB');
        $this->pdo->exec('CREATE TABLE fuzzy_correlate_ssdeep (id INT AUTO_INCREMENT PRIMARY KEY, chunk VARCHAR(12) NOT NULL, attribute_id INT NOT NULL) ENGINE=InnoDB');
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

    /** Rows quickDelete() removes through reports, scanned attributes and ssdeep chunks, next to rows of event 2. */
    private function seedQuickDeleteChildren($mode): void
    {
        if ($mode !== 'quick') {
            return;
        }
        $this->pdo->exec("INSERT INTO attributes (id, event_id, type) VALUES (11, 1, 'attachment'), (12, 1, 'ssdeep'), (13, 2, 'attachment')");
        $this->pdo->exec("INSERT INTO shadow_attributes VALUES (20, 1, 'malware-sample')");
        $this->pdo->exec('INSERT INTO event_reports VALUES (30, 1), (31, 2)');
        $this->pdo->exec('INSERT INTO event_report_tags (event_report_id) VALUES (30), (31)');
        $this->pdo->exec("INSERT INTO attachment_scans (type, attribute_id) VALUES ('Attribute', 11), ('ShadowAttribute', 20), ('Attribute', 13)");
        $this->pdo->exec("INSERT INTO fuzzy_correlate_ssdeep (chunk, attribute_id) VALUES ('chunk', 12), ('chunk', 13)");
        $this->pdo->exec('INSERT INTO event_graph VALUES (40, 1)');
        $this->pdo->exec('INSERT INTO shadow_attribute_correlations VALUES (50, 1, 2), (51, 2, 1), (52, 2, 2)');
        $this->attributeRows = 4;
        $this->quickDeleteSurvivors = ['attributes' => 1, 'shadow_attributes' => 0, 'event_reports' => 1, 'event_report_tags' => 1,
            'attachment_scans' => 1, 'fuzzy_correlate_ssdeep' => 1, 'event_graph' => 0, 'shadow_attribute_correlations' => 1];
    }

    private function childRows(): array
    {
        $rows = [];
        foreach (['attributes', 'shadow_attributes', 'event_reports', 'event_report_tags', 'attachment_scans', 'fuzzy_correlate_ssdeep', 'event_graph', 'shadow_attribute_correlations'] as $table) {
            $rows[$table] = (int)$this->observer->query("SELECT COUNT(*) FROM $table")->fetchColumn();
        }
        return $rows;
    }

    private function rejectDirtyInsert(): void
    {
        $this->pdo->exec("CREATE TRIGGER reject_dirty BEFORE INSERT ON admin_settings FOR EACH ROW BEGIN IF NEW.setting LIKE 'fastLookupIndex:dirty:%' THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'deliberate dirty marker failure'; END IF; END");
    }

    /** @dataProvider deletionModes */
    public function testFailedMarkerRollsBackDeletionAndNestedCallbackSave($mode): void
    {
        $this->seedQuickDeleteChildren($mode);
        $children = $this->childRows();
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
        $this->assertSame($this->attributeRows, (int)$this->observer->query('SELECT COUNT(*) FROM attributes')->fetchColumn());
        $this->assertSame($children, $this->childRows());
        $this->assertSame(0, (int)$this->observer->query('SELECT COUNT(*) FROM deletion_audit')->fetchColumn());
        $this->assertFalse($this->pdo->inTransaction());
        $this->assertTrue($this->db->begin(), 'Cake transaction bookkeeping must remain usable.');
        $this->assertTrue($this->db->rollback());
    }

    /** @dataProvider deletionModes */
    public function testSuccessfulDeletionCommitsMarkerAndNestedCallbackSave($mode): void
    {
        $this->seedQuickDeleteChildren($mode);
        $model = $this->model($mode);
        $model->nestedSave = true;
        $this->assertTrue($this->delete($model, $mode));
        $table = $mode === 'attribute' ? 'attributes' : 'events';
        $this->assertSame(0, (int)$this->observer->query("SELECT COUNT(*) FROM $table")->fetchColumn());
        $this->assertSame(1, (int)$this->observer->query("SELECT COUNT(*) FROM admin_settings WHERE setting LIKE 'fastLookupIndex:dirty:%'")->fetchColumn());
        $this->assertSame(1, (int)$this->observer->query('SELECT COUNT(*) FROM deletion_audit')->fetchColumn());
        $this->assertFalse($this->pdo->inTransaction());
        if ($mode === 'quick') {
            $this->assertSame($this->quickDeleteSurvivors, $this->childRows());
        }
    }

    /** @dataProvider deletionModes */
    public function testCallerCakeTransactionRetainsDeletionMarkerAndNestedSave($mode): void
    {
        $this->seedQuickDeleteChildren($mode);
        $children = $this->childRows();
        $model = $this->model($mode);
        $model->nestedSave = true;
        $this->db->begin();
        $this->assertTrue($this->delete($model, $mode));
        $this->assertTrue($this->pdo->inTransaction());
        $this->assertSame(0, (int)$this->observer->query("SELECT COUNT(*) FROM admin_settings WHERE setting LIKE 'fastLookupIndex:dirty:%'")->fetchColumn());
        $this->db->rollback();
        $this->assertSame(1, (int)$this->observer->query('SELECT COUNT(*) FROM events')->fetchColumn());
        $this->assertSame($this->attributeRows, (int)$this->observer->query('SELECT COUNT(*) FROM attributes')->fetchColumn());
        $this->assertSame($children, $this->childRows());
        $this->assertSame(0, (int)$this->observer->query('SELECT COUNT(*) FROM deletion_audit')->fetchColumn());
    }

    /** @dataProvider deletionModes */
    public function testCallerPdoTransactionIsNotCommittedOrRolledBackOnFailure($mode): void
    {
        $this->seedQuickDeleteChildren($mode);
        $children = $this->childRows();
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
        $this->assertSame($this->attributeRows, (int)$this->observer->query('SELECT COUNT(*) FROM attributes')->fetchColumn());
        $this->assertSame($children, $this->childRows());
    }

    public function testHardDeletingSoftDeletedAttributeKeepsAttributeCount(): void
    {
        // A soft delete already decremented attribute_count; the hard delete by
        // ID must still record the IOC index change without decrementing again.
        $this->pdo->exec("ALTER TABLE attributes ADD value1 TEXT NOT NULL DEFAULT '192.0.2.1', ADD value2 TEXT NOT NULL DEFAULT '', ADD deleted BOOLEAN NOT NULL DEFAULT FALSE");
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
        $this->seedQuickDeleteChildren('quick');
        $children = $this->childRows();
        $model = $this->model('quick');
        $model->veto = true;
        $this->assertFalse($this->delete($model, 'quick'));
        $this->assertSame($this->attributeRows, (int)$this->observer->query('SELECT COUNT(*) FROM attributes')->fetchColumn());
        $this->assertSame($children, $this->childRows());
        $this->assertSame(1, (int)$this->observer->query('SELECT COUNT(*) FROM events')->fetchColumn());
        $this->assertFalse($this->pdo->inTransaction());
    }
}
