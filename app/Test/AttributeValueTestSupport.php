<?php
/**
 * Fakes for AttributeValueTest. Not a test file. Required from setUp, see
 * AttributeValueClassSupport.php.
 */

require_once __DIR__ . '/AttributeValueClassSupport.php';

class AttributeValueFakeStatement
{
    private $rows;

    public function __construct(array $rows)
    {
        $this->rows = $rows;
    }

    public function fetchAll($mode = null)
    {
        return $this->rows;
    }

    public function closeCursor()
    {
        return true;
    }
}

trait AttributeValueFakeDictionary
{
    /** @var string[] */
    public $statements = [];

    /** @var array hex hash => ['id' => int, 'value' => string] */
    public $rows = [];

    /** @var array hex hash => value, what an INSERT of that hash stores */
    public $known = [];

    /** @var bool */
    public $dropInserts = false;

    /** @var array hex hash => true, rows only a locking read sees */
    public $hidden = [];

    /** @var PDOException[] Thrown by the next INSERTs, one each */
    public $insertErrors = [];

    /** @var callable|null Answers any other SELECT. */
    public $responder;

    private $nextId = 1;

    public function rawQuery($sql, $params = array())
    {
        $this->statements[] = $sql;
        if (strpos($sql, 'INSERT INTO') === 0) {
            if (!empty($this->insertErrors)) {
                throw array_shift($this->insertErrors);
            }
            foreach ($this->hashesIn($sql) as $hash) {
                if (!$this->dropInserts && !isset($this->rows[$hash])) {
                    $this->rows[$hash] = ['id' => $this->nextId++, 'value' => $this->known[$hash]];
                }
            }
            return true;
        }
        if (preg_match('/WHERE \W?hash\W? (IN|=)/', $sql)) {
            $locking = strpos($sql, 'LOCK IN SHARE MODE') !== false;
            $out = [];
            foreach ($this->hashesIn($sql) as $hash) {
                if (isset($this->rows[$hash]) && ($locking || !isset($this->hidden[$hash]))) {
                    $out[] = [
                        'id' => (string)$this->rows[$hash]['id'],
                        'value' => $this->rows[$hash]['value'],
                        'hash' => $this->storedHash(hex2bin($hash)),
                    ];
                }
            }
            return new AttributeValueFakeStatement($out);
        }
        $responder = $this->responder;
        return new AttributeValueFakeStatement($responder ? $responder($sql) : []);
    }

    public function store($value, $id = null, $hashOf = null)
    {
        $hash = bin2hex(substr(hash('sha256', $hashOf === null ? $value : $hashOf, true), 0, 16));
        $this->rows[$hash] = ['id' => $id === null ? $this->nextId++ : $id, 'value' => $value];
        return $this->rows[$hash]['id'];
    }

    public function allow(array $values)
    {
        foreach ($values as $value) {
            $this->known[bin2hex(substr(hash('sha256', $value, true), 0, 16))] = $value;
        }
    }

    public function statementsLike($pattern)
    {
        return array_values(preg_grep($pattern, $this->statements));
    }

    private function hashesIn($sql)
    {
        preg_match_all("/(?:X'|decode\(')([0-9a-f]{32})'/", $sql, $matches);
        return $matches[1];
    }
}

class AttributeValueFakeMysql extends MigrationTestMysqlExtended
{
    use AttributeValueFakeDictionary;

    private function storedHash($bytes)
    {
        return $bytes;
    }
}

class AttributeValueFakePostgres extends MigrationTestPostgres
{
    use AttributeValueFakeDictionary;

    // pdo_pgsql hands bytea back as a stream
    private function storedHash($bytes)
    {
        $stream = fopen('php://memory', 'r+');
        fwrite($stream, $bytes);
        rewind($stream);
        return $stream;
    }
}

class TestAttributeValue extends AttributeValue
{
    /** @var array value => the value whose hash it is given */
    public $collisions = [];

    /** @var bool */
    public $transaction = false;

    /** @var bool Whether a find is in progress to take association rows */
    public $findInProgress = false;

    /** @var int */
    public $deferredCalls = 0;

    private $fakeDb;

    private $fakeDialect;

    public function __construct($db)
    {
        $this->fakeDb = $db;
        $this->fakeDialect = new SqlDialect($db);
    }

    public function getDataSource()
    {
        return $this->fakeDb;
    }

    public function getSqlDialect()
    {
        return $this->fakeDialect;
    }

    public function hashOf($value)
    {
        return parent::hashOf(isset($this->collisions[$value]) ? $this->collisions[$value] : $value);
    }

    protected function inTransaction()
    {
        return $this->transaction;
    }

    protected function deferRows()
    {
        $this->deferredCalls++;
        return $this->findInProgress;
    }
}
