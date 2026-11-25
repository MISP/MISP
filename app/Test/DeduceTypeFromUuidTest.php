<?php
/**
 * AppModel::deduceTypeFromUuid() delegation tests.
 *
 * Pure PHPUnit, no CakePHP bootstrap, no DB — the convention used by every
 * other test under app/Test/ (see CollectionCaptureTest). The shared uuid
 * lookup is reached through three callers, each of which has to hand it its
 * own candidate list, so we drive them through subclasses that record what
 * the helper was called with.
 *
 * AnalystData::deduceType() is the regression that matters: it used to walk
 * $this->valid_targets, but valid_targets is a class *constant*, so the
 * property lookup yielded null, the loop never ran and every call ended in
 * NotFoundException('Invalid UUID').
 */

require_once __DIR__ . '/../Vendor/autoload.php';

// -------- framework stubs (must exist BEFORE the models load) --------

if (!class_exists('App', false)) {
    class App
    {
        public static function uses($class, $package)
        {
        }
    }
}

if (!function_exists('__')) {
    function __($string)
    {
        $args = func_get_args();
        $format = array_shift($args);
        return empty($args) ? $format : vsprintf($format, $args);
    }
}

// NB: this AppModel stub is shared with the Collection*Test files. They all
// guard with class_exists(), so in a full-suite run whichever loads first wins
// for everyone — hence the identical shape here.
if (!class_exists('AppModel', false)) {
    class AppModel
    {
        public $alias = 'Collection';
        public $id = false;
        public $data = array();
        public $validationErrors = array();

        public function create($data = array())
        {
            $this->id = false;
        }

        public function save($data = null, $validate = true, $fieldList = array())
        {
            return true;
        }

        public function find($type, $options = array())
        {
            return array();
        }
    }
}

require_once __DIR__ . '/../Model/AnalystData.php';
require_once __DIR__ . '/../Model/CollectionElement.php';

use PHPUnit\Framework\TestCase;

/** AnalystData with the shared lookup replaced by a recorder. */
class DeduceTypeRecordingAnalystData extends AnalystData
{
    public $passedUuid = null;
    public $passedCandidates = null;

    protected function deduceTypeFromUuid(string $uuid, array $candidateModels)
    {
        $this->passedUuid = $uuid;
        $this->passedCandidates = $candidateModels;
        return $candidateModels[0];
    }
}

/** CollectionElement with the shared lookup replaced by a recorder. */
class DeduceTypeRecordingCollectionElement extends CollectionElement
{
    public $passedUuid = null;
    public $passedCandidates = null;

    protected function deduceTypeFromUuid(string $uuid, array $candidateModels)
    {
        $this->passedUuid = $uuid;
        $this->passedCandidates = $candidateModels;
        return $candidateModels[0];
    }
}

class DeduceTypeFromUuidTest extends TestCase
{
    const UUID = '9d5b7bbc-8f1b-4f3e-9a24-3f1f0a4d2b6c';

    /**
     * AnalystData's constructor calls parent::__construct() and bindModel(),
     * which the framework-less AppModel stub does not provide. The lookup
     * needs no instance state, so build the model without the constructor.
     */
    private function analystData()
    {
        $class = new ReflectionClass('DeduceTypeRecordingAnalystData');
        return $class->newInstanceWithoutConstructor();
    }

    public function testDeduceTypeLooksInEveryAnalystDataTarget(): void
    {
        $model = $this->analystData();
        $this->assertSame('Attribute', $model->deduceType(self::UUID));
        $this->assertSame(self::UUID, $model->passedUuid);
        $this->assertSame(AnalystData::valid_targets, $model->passedCandidates);
    }

    public function testGetAnalystDataTypeFromUUIDLooksInTheAnalystDataTypes(): void
    {
        $model = $this->analystData();
        $this->assertSame('Note', $model->getAnalystDataTypeFromUUID(self::UUID));
        $this->assertSame(self::UUID, $model->passedUuid);
        $this->assertSame(AnalystData::ANALYST_DATA_TYPES, $model->passedCandidates);
    }

    public function testCollectionElementDeduceTypeLooksInItsValidTypes(): void
    {
        $model = new DeduceTypeRecordingCollectionElement();
        $this->assertSame('Event', $model->deduceType(self::UUID));
        $this->assertSame(self::UUID, $model->passedUuid);
        $this->assertSame(['Event', 'GalaxyCluster'], $model->passedCandidates);
    }
}
