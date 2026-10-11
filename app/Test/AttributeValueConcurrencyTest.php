<?php
/**
 * AttributeValue interns racing each other in separate processes against the
 * configured MySQL/MariaDB database.
 *
 * The workers commit, so they intern into a scratch copy of attribute_values
 * that is created and dropped around each test. Skipped unless
 * ATTRIBUTE_VALUE_DB_TESTS is set, and it boots the real application, so it
 * must run on its own:
 *     ATTRIBUTE_VALUE_DB_TESTS=1 ./app/Vendor/bin/phpunit app/Test/AttributeValueConcurrencyTest.php
 */

use PHPUnit\Framework\TestCase;

class AttributeValueConcurrencyTest extends TestCase
{
    const TABLE = 'attribute_values_concurrency';

    private static $booted = false;

    /** @var AttributeValue */
    private $model;

    /** @var DboSource */
    private $db;

    /** @var AttributeValueWorkerPool|null */
    private $pool;

    /** @var string */
    private $token;

    protected function setUp(): void
    {
        if (!getenv('ATTRIBUTE_VALUE_DB_TESTS')) {
            $this->markTestSkipped('Needs the database, see the file header.');
        }
        if (!self::$booted) {
            if (class_exists('App', false)) {
                $this->markTestSkipped('Needs its own process: run this file alone.');
            }
            require_once __DIR__ . '/OracleBootstrap.php';
            require_once __DIR__ . '/AttributeValueConcurrencySupport.php';
            App::uses('ClassRegistry', 'Utility');
            App::uses('ConnectionManager', 'Model');
            self::$booted = true;
        }
        $this->db = ConnectionManager::getDataSource('default');
        if (!($this->db instanceof Mysql)) {
            // Skipped before the fixture exists: nothing for tearDown to clean up
            $this->db = null;
            $this->markTestSkipped('MySQL/MariaDB only.');
        }
        // The scratch table is newer than any cached table list
        $this->db->cacheSources = false;
        $this->db->rawQuery('DROP TABLE IF EXISTS ' . self::TABLE);
        $this->db->rawQuery(sprintf('CREATE TABLE %s LIKE attribute_values', self::TABLE));
        $this->model = ClassRegistry::init(['class' => 'AttributeValue', 'table' => self::TABLE]);
        $this->token = 'avtest' . bin2hex(random_bytes(4));
    }

    protected function tearDown(): void
    {
        if ($this->pool) {
            $this->pool->close();
        }
        if ($this->model) {
            $this->db->rawQuery('DROP TABLE IF EXISTS ' . self::TABLE);
        }
    }

    private function pool($size)
    {
        $this->pool = new AttributeValueWorkerPool($this->db->config, self::TABLE, $size);
        return $this->pool;
    }

    public function testParallelInternsAgreeOnOneRowPerValue()
    {
        $run = AttributeValueConcurrency::run($this->pool(8), $this->token, 3, 2000, 1200, false);

        $this->assertSame([], AttributeValueConcurrency::failures($run['replies']));
        $this->assertSame([], AttributeValueConcurrency::problems($this->model, $run['batches'], $run['replies']));
        $statement = $this->db->rawQuery('SELECT COUNT(*) FROM ' . self::TABLE);
        $this->assertSame($run['values'], (int)$statement->fetchColumn());
        $statement->closeCursor();
    }

    /**
     * The database rolls back a deadlocked transaction as a whole, so the
     * model cannot retry it; the caller sees the deadlock.
     */
    public function testInternsInsideTransactionsFailOnlyByDeadlock()
    {
        $run = AttributeValueConcurrency::run($this->pool(8), $this->token, 2, 1000, 600, true);

        foreach (AttributeValueConcurrency::failures($run['replies']) as $error) {
            $this->assertSame(1213, $error['code'], json_encode($error));
        }
        $this->assertSame([], AttributeValueConcurrency::problems($this->model, $run['batches'], $run['replies']));
    }

    public function testInternSeesAValueCommittedAfterTheSnapshot()
    {
        $result = AttributeValueConcurrency::internAfterSnapshot($this->pool(2), $this->token . ' late');

        $this->assertTrue($result['hidden'], 'The snapshot should hide the later commit.');
        $this->assertTrue($result['reply']['ok'], json_encode($result['reply']));
        $this->assertSame([$result['committed']], $result['reply']['ids']);
    }

    public function testInternWaitsForAnUncommittedInsertOfTheSameValue()
    {
        $pool = $this->pool(2);

        $committed = AttributeValueConcurrency::internWhileHeld($pool, $this->token . ' committed', 'commit');
        $rolledBack = AttributeValueConcurrency::internWhileHeld($pool, $this->token . ' rolled back', 'rollback');

        $this->assertTrue($committed['waited']);
        $this->assertSame([$committed['held']], $committed['reply']['ids']);
        $this->assertTrue($rolledBack['waited']);
        $this->assertTrue($rolledBack['reply']['ok'], json_encode($rolledBack['reply']));
        $this->assertNotSame($rolledBack['held'], $rolledBack['reply']['ids'][0]);
        $this->assertSame($committed['held'], $this->model->intern($this->token . ' committed'));
        $this->assertSame($rolledBack['reply']['ids'][0], $this->model->intern($this->token . ' rolled back'));
    }

    public function testAnOpenTransactionDoesNotBlockOtherInterns()
    {
        $values = [];
        for ($i = 0; $i < 300; $i++) {
            $values[] = "{$this->token} held $i";
        }

        $result = AttributeValueConcurrency::internBesideOpenTransaction($this->pool(2), $values, $this->token . ' other');

        $this->assertTrue($result['held']['ok'], json_encode($result['held']));
        $this->assertSame($result['late'], $result['held']['ids'][0]);
        $this->assertFalse($result['blocked']);
        $this->assertTrue($result['reply']['ok'], json_encode($result['reply']));
    }
}
