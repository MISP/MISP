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

    /** @var array Thrown by the next INSERTs, one each; null lets one through */
    public $insertErrors = [];

    /** @var callable|null Answers any other SELECT. */
    public $responder;

    private $nextId = 1;

    public function rawQuery($sql, $params = array())
    {
        $this->statements[] = $sql;
        if (strpos($sql, 'INSERT INTO') === 0) {
            if (!empty($this->insertErrors) && ($error = array_shift($this->insertErrors)) !== null) {
                throw $error;
            }
            if (strpos($sql, 'value_ip_ranges') !== false) {
                return true;
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
        $hash = hash('sha256', $hashOf === null ? $value : $hashOf);
        $this->rows[$hash] = ['id' => $id === null ? $this->nextId++ : $id, 'value' => $value];
        return $this->rows[$hash]['id'];
    }

    public function allow(array $values)
    {
        foreach ($values as $value) {
            $this->known[hash('sha256', $value)] = $value;
        }
    }

    public function statementsLike($pattern)
    {
        return array_values(preg_grep($pattern, $this->statements));
    }

    private function hashesIn($sql)
    {
        preg_match_all("/(?:X'|decode\(')([0-9a-f]{64})'/", $sql, $matches);
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

    /** @var string[]|null What the find in progress holds for its primary rows */
    public $valueKeys = null;

    /** @var bool False for a find in progress asked for valueText => false */
    public $textWanted = true;

    /** @var array Each set of value keys a field list asked for */
    public $askedKeys = [];

    /** @var string */
    public $collation = 'utf8mb4_uca1400_ai_ci';

    /** @var int[] innodb_ft_min_token_size and innodb_ft_max_token_size */
    public $ftTokenSizes = [3, 84];

    /** @var bool */
    public $indexHoldsStopwords = true;

    /** @var int */
    public $stopwordChecks = 0;

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

    protected function valueCollation()
    {
        return $this->collation;
    }

    protected function deferRows()
    {
        $this->deferredCalls++;
        return $this->findInProgress;
    }

    protected function textWanted()
    {
        return $this->textWanted;
    }

    protected function findValueKeys()
    {
        return $this->valueKeys;
    }

    protected function askValueKeys(array $keys)
    {
        $this->askedKeys[] = $keys;
    }

    protected function fulltextTokenSizes()
    {
        return $this->ftTokenSizes;
    }

    protected function searchIndexHoldsStopwords()
    {
        $this->stopwordChecks++;
        return $this->indexHoldsStopwords;
    }
}
