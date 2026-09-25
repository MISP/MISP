<?php

use PHPUnit\Framework\TestCase;

/** No framework stubs: this suite is safe beside the isolated controller suites. */
class FastLookupIndexTest extends TestCase
{
    protected function setUp(): void
    {
        require_once __DIR__ . '/../Lib/Tools/FastLookupIndex.php';
    }

    private function index($scope = null)
    {
        $unavailable = new class {
            public function __call($method, $args) { throw new RuntimeException('Disconnected.'); }
        };
        return new FastLookupIndex('test-database', $scope ?? ['attribute_types' => ['domain'], 'published_only' => true], $unavailable);
    }

    /** @dataProvider invalidScopes */
    public function testInvalidScopeCannotInitializeAnIndex($scope): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->index($scope);
    }

    public function invalidScopes(): array
    {
        return [[[]], [['attribute_types' => []]], [['attribute_types' => 'domain']],
            [['attribute_types' => ['']]], [['attribute_types' => [42]]],
            [['attribute_types' => ["domain\0hostname"]]],
            [['attribute_types' => ['domain'], 'published_only' => 'true']]];
    }

    public function testUnavailableRedisCannotProduceEmptyMetadata(): void
    {
        $this->expectException(FastLookupIndexUnavailableException::class);
        $this->index()->metadata();
    }

    /** @dataProvider invalidAttributes */
    public function testMalformedPreparedAttributesAreRejectedBeforeIndexWrites($row): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->index()->addAttributes('generation', '1', [$row]);
    }

    public function invalidAttributes(): array
    {
        $token = 'E' . str_repeat('x', 16);
        return [[[]], [['id' => '0', 'type' => 'domain', 'tokens' => [$token]]],
            [['id' => '01', 'type' => 'domain', 'tokens' => [$token]]],
            [['id' => 1, 'type' => 'domain', 'tokens' => [$token]]],
            [['id' => '1', 'type' => 'ip-src', 'tokens' => [$token]]],
            [['id' => '1', 'type' => 'domain', 'tokens' => ['example.org']]],
            [['id' => '1', 'type' => 'domain', 'tokens' => ['X' . str_repeat('x', 16)]]],
            [['id' => '1', 'type' => 'domain', 'tokens' => [str_repeat('E', 18)]]]];
    }

    public function testOversizedWriteBatchFailsRatherThanDroppingAttributes(): void
    {
        $this->expectException(OverflowException::class);
        $this->index()->addAttributes('generation', '1', array_fill(0, 501, []));
    }

    public function testOversizedAttributeFailsRatherThanDroppingTokens(): void
    {
        $this->expectException(OverflowException::class);
        $this->index()->addAttributes('generation', '1', [['id' => '1', 'type' => 'domain',
            'tokens' => array_fill(0, 1025, 'E' . str_repeat('x', 16))]]);
    }

    /** @dataProvider invalidQueries */
    public function testInvalidQueryPlanCannotBeInterpretedAsANegativeMatch($plan): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->index()->candidates('generation', $plan);
    }

    public function invalidQueries(): array
    {
        return [[[null]], [[[[]]]],
            [[[['type' => 'domain', 'token' => 'E' . str_repeat('x', 16), 'kind' => 'domain']]]],
            [[[['type' => 'ip-src', 'token' => 'I' . str_repeat('x', 16), 'kind' => 'ip_range']]]]];
    }

    public function testMalformedStoredMetadataFailsClosed(): void
    {
        $redis = new class {
            public function hGetAll($key)
            {
                return ['schema' => '2', 'generation' => 'generation', 'fingerprint' => 'fingerprint',
                    'revision' => '1', 'ready' => '1', 'scope' => '{}', 'progress' => '{'];
            }
        };
        $index = new FastLookupIndex('db', ['attribute_types' => ['domain']], $redis);
        $this->expectException(FastLookupIndexUnavailableException::class);
        $index->metadata();
    }
}
