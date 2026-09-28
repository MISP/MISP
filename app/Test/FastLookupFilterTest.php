<?php

use PHPUnit\Framework\TestCase;

/**
 * Framework-free, Redis-free coverage of FastLookupFilter's validation paths:
 * everything the class rejects before it would touch Redis. No container,
 * no CakePHP bootstrap — safe to run in plain CI PHPUnit.
 *
 * Ported from the deleted app/Test/FastLookupIndexTest.php (see
 * `git show 28b587103^:app/Test/FastLookupIndexTest.php`) onto
 * FastLookupFilter's current API. Divergences from the old test are called
 * out per case below; a couple of old cases have no equivalent any more
 * because FastLookupFilter validates less than FastLookupIndex did (no
 * attribute `type` check in add(), no batch-size cap) — those are listed at
 * the bottom instead of being silently dropped.
 */
class FastLookupFilterTest extends TestCase
{
    protected function setUp(): void
    {
        require_once __DIR__ . '/../Lib/Tools/FastLookupFilter.php';
    }

    /** A connection double that fails any call, so a test only passes when validation throws first. */
    private function disconnected()
    {
        return new class {
            public function __call($method, $args)
            {
                throw new RuntimeException('Disconnected.');
            }
        };
    }

    private function filter($scope = null, $redis = null)
    {
        return new FastLookupFilter('test-database', $scope ?? ['attribute_types' => ['domain'], 'published_only' => true],
            $redis ?? $this->disconnected());
    }

    private function token(string $prefix): string
    {
        return $prefix . str_repeat('x', 8);
    }

    // -- constructor / scope -------------------------------------------------

    /** @dataProvider invalidScopes */
    public function testInvalidScopeCannotConstructAFilter($scope): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->filter($scope);
    }

    public function invalidScopes(): array
    {
        return [
            'empty scope' => [[]],
            'empty type list' => [['attribute_types' => []]],
            'type list not an array' => [['attribute_types' => 'domain']],
            'empty type string' => [['attribute_types' => ['']]],
            'non-string type' => [['attribute_types' => [42]]],
            'type with a null byte' => [['attribute_types' => ["domain\0hostname"]]],
            'type over 255 bytes' => [['attribute_types' => [str_repeat('a', 256)]]],
            'published_only not boolean' => [['attribute_types' => ['domain'], 'published_only' => 'true']],
        ];
    }

    // -- metadata() with no usable Redis -------------------------------------

    public function testUnavailableRedisCannotProduceEmptyMetadata(): void
    {
        $this->expectException(FastLookupIndexUnavailableException::class);
        $this->filter()->metadata();
    }

    // -- add(): malformed prepared rows and tokens ---------------------------

    /**
     * @dataProvider invalidPreparedRows
     * Ported from FastLookupIndexTest::invalidAttributes. The old
     * addAttributes(generation, revision, rows) also rejected a row whose
     * 'type' disagreed with the scope (e.g. type 'ip-src' in a domain-only
     * scope); FastLookupFilter::add() has no revision parameter and no
     * longer looks at 'type' at all (id/tokens only), so that case is
     * dropped here rather than faked into a false pass.
     */
    public function testMalformedPreparedRowsAreRejectedBeforeAnyRedisWrite($row): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->filter()->add('generation', [$row]);
    }

    public function invalidPreparedRows(): array
    {
        $token = $this->token('E');
        return [
            'empty row' => [[]],
            'id with leading zero digit only' => [['id' => '0', 'tokens' => [$token]]],
            'id with leading zero' => [['id' => '01', 'tokens' => [$token]]],
            'id not a string' => [['id' => 1, 'tokens' => [$token]]],
            'tokens not an array' => [['id' => '1', 'tokens' => 'not-an-array']],
            'token of the wrong length' => [['id' => '1', 'tokens' => ['example.org']]],
            'token with an unknown kind prefix' => [['id' => '1', 'tokens' => [$this->token('X')]]],
            'token 9 bytes over budget' => [['id' => '1', 'tokens' => [str_repeat('E', 18)]]],
        ];
    }

    public function testOversizedAttributeFailsRatherThanDroppingTokens(): void
    {
        $this->expectException(OverflowException::class);
        $this->filter()->add('generation', [['id' => '1', 'tokens' => array_fill(0, 1025, $this->token('E'))]]);
    }

    // -- identifier() validation across call sites ---------------------------

    /**
     * @dataProvider invalidIdentifiers
     * add() validates its $generation argument with identifier() before it
     * ever reaches Redis, so this exercises the shared identifier() guard
     * (empty, disallowed characters, over 128 bytes, embedded NUL) without
     * needing a connection.
     */
    public function testInvalidGenerationIsRejectedBeforeAnyRedisCall($generation): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->filter()->add($generation, []);
    }

    public function invalidIdentifiers(): array
    {
        return [
            'empty string' => [''],
            'contains a space' => ['bad generation'],
            'over 128 bytes' => [str_repeat('a', 129)],
            'embedded NUL' => ["gen\0eration"],
        ];
    }

    public function testInvalidGenerationIsRejectedByCandidatesBeforeTheBudgetOrPlanIsChecked(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->filter()->candidates('bad generation', []);
    }

    public function testInvalidGenerationIsRejectedByActivateBeforeAnyRedisCall(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->filter()->activate('bad generation', 'fingerprint');
    }

    public function testInvalidRevisionIsRejectedByCheckpointBeforeAnyRedisCall(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->filter()->checkpoint('bad revision', true);
    }

    public function testInvalidCursorIsRejectedBySetCursor(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->filter()->setCursor('generation', 'not-a-decimal-id');
    }

    // -- candidates(): invalid query plans ------------------------------------

    /**
     * @dataProvider invalidQueryPlans
     * Ported from FastLookupIndexTest::invalidQueries onto the current
     * candidates(generation, queryTokens, maximumIds) shape, whose entries
     * are ['token' => ..., 'kind' => ...] (the old 'type' key is gone).
     * All of this validation runs before candidates() calls metadata(), so
     * the disconnected double never gets invoked.
     */
    public function testInvalidQueryPlanCannotBeInterpretedAsANegativeMatch($plan): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->filter()->candidates('generation', $plan);
    }

    public function invalidQueryPlans(): array
    {
        return [
            'position value is not a token list' => [[null]],
            'entry is not an array' => [[['not-an-array']]],
            'entry missing token/kind' => [[[[]]]],
            'entry token has the wrong shape' => [[[['token' => 'bad', 'kind' => 'exact']]]],
            'entry kind disagrees with the token prefix' => [[[['token' => $this->token('E'), 'kind' => 'domain']]]],
        ];
    }

    /** @dataProvider invalidCandidateBudgets */
    public function testInvalidCandidateBudgetIsRejectedBeforeThePlanIsRead($maximumIds): void
    {
        $this->expectException(InvalidArgumentException::class);
        // A plan that would itself be invalid too, to prove the budget check runs first.
        $this->filter()->candidates('generation', [null], $maximumIds);
    }

    public function invalidCandidateBudgets(): array
    {
        return [
            'zero' => [0],
            'negative' => [-1],
            'over the 500000 cap' => [500001],
        ];
    }

    // -- reserve(): invalid sizing --------------------------------------------

    /**
     * @dataProvider invalidReserveCalls
     * reserve() validates generation, fingerprint and sizing before it reads
     * or writes anything in Redis (the live-generation lookup only happens
     * after these checks), so the disconnected double is never invoked.
     */
    public function testReserveRejectsInvalidIdentifiersAndSizing($generation, $fingerprint, $capacity, $rate, $rangeEntries): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->filter()->reserve($generation, $fingerprint, $capacity, $rate, $rangeEntries);
    }

    public function invalidReserveCalls(): array
    {
        return [
            'invalid generation identifier' => ['bad generation', 'fingerprint', 1000000, 0.001, 0],
            'invalid fingerprint identifier' => ['generation', 'bad fingerprint', 1000000, 0.001, 0],
            'zero capacity' => ['generation', 'fingerprint', 0, 0.001, 0],
            'negative capacity' => ['generation', 'fingerprint', -1, 0.001, 0],
            'zero rate' => ['generation', 'fingerprint', 1000000, 0.0, 0],
            'rate at 1' => ['generation', 'fingerprint', 1000000, 1.0, 0],
            'rate over 1' => ['generation', 'fingerprint', 1000000, 1.5, 0],
            'negative range entries' => ['generation', 'fingerprint', 1000000, 0.001, -1],
        ];
    }

    // -- pure helpers ----------------------------------------------------------

    public function testBucketsForRoundsUpToTheNext64EntryBucket(): void
    {
        $this->assertSame(1, FastLookupFilter::bucketsFor(0));
        $this->assertSame(1, FastLookupFilter::bucketsFor(1));
        $this->assertSame(1, FastLookupFilter::bucketsFor(64));
        $this->assertSame(2, FastLookupFilter::bucketsFor(65));
        $this->assertSame(2, FastLookupFilter::bucketsFor(128));
        $this->assertSame(3, FastLookupFilter::bucketsFor(129));
    }

    public function testBucketsForNeverExceedsTheMaximum(): void
    {
        $this->assertSame(4194304, FastLookupFilter::bucketsFor(PHP_INT_MAX >> 8));
    }

    public function testEstimatedFalsePositiveRateIsZeroWithNothingInserted(): void
    {
        $this->assertSame(0.0, FastLookupFilter::estimatedFalsePositiveRate(1000000, 0.001, 0));
    }

    public function testEstimatedFalsePositiveRateMatchesTheDocumentedFormula(): void
    {
        $capacity = 1000000;
        $rate = 0.001;
        $inserted = 500000;
        $hashes = (int)ceil(-log($rate) / log(2));
        $bits = -log($rate) / (log(2) ** 2) * $capacity;
        $expected = (1 - exp(-$hashes * $inserted / $bits)) ** $hashes;
        $this->assertSame($expected, FastLookupFilter::estimatedFalsePositiveRate($capacity, $rate, $inserted));
    }

    public function testEstimatedFalsePositiveRateIncreasesAsMoreIsInserted(): void
    {
        $low = FastLookupFilter::estimatedFalsePositiveRate(1000000, 0.001, 100000);
        $high = FastLookupFilter::estimatedFalsePositiveRate(1000000, 0.001, 900000);
        $this->assertGreaterThan($low, $high);
    }

    // -- metadata(): corrupt Redis state must fail closed ----------------------

    /** Every field a healthy FastLookupFilter::metadata() would read successfully, for the default test scope. */
    private function validMetadataFields(): array
    {
        return [
            'schema' => FastLookupFilter::SCHEMA,
            'live' => '',
            'building' => '',
            'fingerprint' => '',
            'building_fingerprint' => '',
            'revision' => '1',
            'ready' => '1',
            'scope' => json_encode(['attribute_types' => ['domain'], 'published_only' => true], JSON_THROW_ON_ERROR),
        ];
    }

    private function metadataDouble(array $overrides, bool $unset = false)
    {
        $fields = $this->validMetadataFields();
        if ($unset) {
            foreach (array_keys($overrides) as $key) { unset($fields[$key]); }
        } else {
            $fields = array_merge($fields, $overrides);
        }
        return new class($fields) {
            private $fields;
            public function __construct(array $fields) { $this->fields = $fields; }
            public function hGetAll($key) { return $this->fields; }
        };
    }

    /** Sanity check: the base fixture is a metadata() success, so the corrupt variants below are testing one thing at a time. */
    public function testValidMetadataFixtureDoesNotThrow(): void
    {
        $meta = $this->filter(null, $this->metadataDouble([]))->metadata();
        $this->assertNull($meta['live']);
        $this->assertTrue($meta['ready']);
    }

    public function testWrongSchemaVersionFailsClosed(): void
    {
        $this->expectException(FastLookupIndexCorruptException::class);
        $this->filter(null, $this->metadataDouble(['schema' => 'v3']))->metadata();
    }

    public function testMissingRequiredFieldFailsClosed(): void
    {
        $this->expectException(FastLookupIndexCorruptException::class);
        $this->filter(null, $this->metadataDouble(['live' => null], true))->metadata();
    }

    public function testReadyOutsideZeroOrOneFailsClosed(): void
    {
        $this->expectException(FastLookupIndexCorruptException::class);
        $this->filter(null, $this->metadataDouble(['ready' => '2']))->metadata();
    }

    public function testCorruptRevisionIdentifierFailsClosed(): void
    {
        $this->expectException(FastLookupIndexCorruptException::class);
        $this->filter(null, $this->metadataDouble(['revision' => 'bad revision!']))->metadata();
    }

    public function testCorruptLiveGenerationIdentifierFailsClosed(): void
    {
        $this->expectException(FastLookupIndexCorruptException::class);
        $this->filter(null, $this->metadataDouble(['live' => 'bad generation!']))->metadata();
    }

    public function testUnparsableScopeJsonFailsClosed(): void
    {
        $this->expectException(FastLookupIndexCorruptException::class);
        $this->filter(null, $this->metadataDouble(['scope' => '{not valid json']))->metadata();
    }

    /** Records every Redis call; $replies maps a method to a value or a Throwable to throw. */
    private function recordingRedis(array $replies)
    {
        return new class($replies) {
            public $calls = [];
            private $replies;
            public function __construct(array $replies) { $this->replies = $replies; }
            public function __call($method, $args)
            {
                $this->calls[] = $method;
                $reply = $this->replies[$method] ?? null;
                if ($reply instanceof Throwable) { throw $reply; }
                return $reply;
            }
        };
    }

    /** @dataProvider transportFailures */
    public function testTransportFailureReadingMetadataIsNotCorruption(array $replies): void
    {
        try {
            $this->filter(null, $this->recordingRedis($replies))->metadata();
            $this->fail('A failed read must fail closed.');
        } catch (FastLookupIndexUnavailableException $e) {
            $this->assertNotInstanceOf(FastLookupIndexCorruptException::class, $e);
        }
    }

    public function transportFailures(): array
    {
        return [
            'timeout' => [['hGetAll' => new RuntimeException('read error on connection')]],
            'refused read' => [['hGetAll' => false, 'getLastError' => 'LOADING Redis is loading the dataset in memory']],
            'BUSY on the generation check' => [['hGetAll' => ['schema' => 'bloom-1', 'live' => 'live1', 'building' => '',
                'fingerprint' => 'f', 'building_fingerprint' => '', 'revision' => '1', 'ready' => '1',
                'scope' => json_encode(['attribute_types' => ['domain'], 'published_only' => true])],
                'eval' => new RuntimeException('BUSY Redis is busy running a script.')]],
        ];
    }

    public function testMissingOrMistypedMetadataIsCorruption(): void
    {
        foreach ([['hGetAll' => []], ['hGetAll' => false, 'getLastError' => 'WRONGTYPE Operation against a key holding the wrong kind of value']] as $replies) {
            try {
                $this->filter(null, $this->recordingRedis($replies))->metadata();
                $this->fail('Missing metadata must fail closed.');
            } catch (FastLookupIndexCorruptException $e) {
                $this->addToAssertionCount(1);
            }
        }
    }

    public function testMissingLiveGenerationIsCorruption(): void
    {
        $this->expectException(FastLookupIndexCorruptException::class);
        $this->filter(null, $this->recordingRedis(['hGetAll' => ['schema' => FastLookupFilter::SCHEMA, 'live' => 'live1', 'building' => '',
            'fingerprint' => 'f', 'building_fingerprint' => '', 'revision' => '1', 'ready' => '1',
            'scope' => json_encode(['attribute_types' => ['domain'], 'published_only' => true])],
            'eval' => new RuntimeException('missing Bloom filter')]))->metadata();
    }

    public function testTransportFailureDuringReserveNeverResetsTheNamespace(): void
    {
        $redis = $this->recordingRedis(['hGetAll' => new RuntimeException('read error on connection')]);
        try {
            $this->filter(null, $redis)->reserve('next', 'fingerprint', 1000, 0.001, 1);
            $this->fail('reserve() must fail when Redis cannot be read.');
        } catch (FastLookupIndexUnavailableException $e) {
            $this->assertNotInstanceOf(FastLookupIndexCorruptException::class, $e);
        }
        $this->assertSame(['hGetAll'], $redis->calls, 'Nothing was deleted, reset or reserved.');
    }

    public function testMissingMetadataDuringReserveStartsACleanNamespace(): void
    {
        $redis = $this->recordingRedis(['hGetAll' => [], 'eval' => 1, 'scan' => []]);
        try {
            $this->filter(null, $redis)->reserve('next', 'fingerprint', 1000, 0.001, 1);
        } catch (FastLookupIndexUnavailableException $e) {
            // The double's SCAN cursor never ends the cleanup; the reset already happened.
        }
        $this->assertSame(['hGetAll', 'del', 'hMSet'], array_slice($redis->calls, 0, 3));
    }

    public function testScopeDisagreeingWithConfigurationFailsClosed(): void
    {
        $this->expectException(FastLookupIndexCorruptException::class);
        $mismatched = json_encode(['attribute_types' => ['hostname'], 'published_only' => true], JSON_THROW_ON_ERROR);
        $this->filter(null, $this->metadataDouble(['scope' => $mismatched]))->metadata();
    }
}

/*
 * Deleted FastLookupIndexTest cases with no FastLookupFilter equivalent
 * (kept here rather than silently dropped, per the task brief):
 *
 * - testOversizedWriteBatchFailsRatherThanDroppingAttributes: the old
 *   addAttributes() capped a single call at 500 attributes and threw
 *   OverflowException over that. FastLookupFilter::add() has no such cap —
 *   FILTER_BATCH/POSTING_BATCH only chunk the Redis round trips, they don't
 *   reject a large $prepared array.
 *
 * - The 'type' mismatch row/entry cases in FastLookupIndexTest's
 *   invalidAttributes/invalidQueries (e.g. an attribute or query token
 *   carrying `'type' => 'ip-src'` under a domain-only scope): add() and
 *   candidates() no longer take or validate a `type` field at all, only
 *   `id`/`tokens` and `token`/`kind` respectively, so there is nothing left
 *   to assert there.
 */
