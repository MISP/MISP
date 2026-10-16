<?php
require_once __DIR__ . '/../Lib/Tools/GalaxyElementFacets.php';

use PHPUnit\Framework\TestCase;

class GalaxyElementFacetsTest extends TestCase
{
    public function testKeysWithRepeatingValuesAreKeptMostUsedFirst()
    {
        $keys = GalaxyElementFacets::selectKeys([
            'attribution-confidence' => ['rows' => 163, 'clusters' => 163, 'values' => 5],
            'country' => ['rows' => 403, 'clusters' => 400, 'values' => 36],
            'external_id' => ['rows' => 596, 'clusters' => 596, 'values' => 593],
            'ISO' => ['rows' => 252, 'clusters' => 252, 'values' => 252],
            'refs' => ['rows' => 2976, 'clusters' => 900, 'values' => 200],
            'since' => ['rows' => 7, 'clusters' => 7, 'values' => 1],
            'odd key' => ['rows' => 100, 'clusters' => 100, 'values' => 3],
        ]);
        $this->assertSame(['country', 'attribution-confidence'], $keys);
    }

    public function testKeysAreCapped()
    {
        $summaries = [];
        for ($i = 0; $i < 10; $i++) {
            $summaries['k' . $i] = ['rows' => 100, 'clusters' => 50 + $i, 'values' => 4];
        }
        $keys = GalaxyElementFacets::selectKeys($summaries);
        $this->assertCount(GalaxyElementFacets::MAX_KEYS, $keys);
        $this->assertSame('k9', $keys[0]);
    }

    public function testValuesMustSurviveTheUrl()
    {
        $this->assertTrue(GalaxyElementFacets::isUsableValue('Russia'));
        $this->assertTrue(GalaxyElementFacets::isUsableValue('mitre-attack:enterprise-attack:persistence'));
        $this->assertFalse(GalaxyElementFacets::isUsableValue('N/A'));
        $this->assertFalse(GalaxyElementFacets::isUsableValue('a||b'));
        $this->assertFalse(GalaxyElementFacets::isUsableValue('!x'));
        $this->assertFalse(GalaxyElementFacets::isUsableValue(' '));
        $this->assertFalse(GalaxyElementFacets::isUsableValue(str_repeat('a', 101)));
    }

    public function testLabels()
    {
        $this->assertSame('Suspected victims', GalaxyElementFacets::label('cfr-suspected-victims'));
        $this->assertSame('Platforms', GalaxyElementFacets::label('mitre_platforms'));
        $this->assertSame('Kill chain', GalaxyElementFacets::label('kill_chain'));
    }

    public function testParamsSplitIntoIncludesAndExcludes()
    {
        $filters = GalaxyElementFacets::filtersFromParams([
            'meta_country' => 'Russia||China||!Iran',
            'meta_motive' => ['Espionage', 'Sabotage'],
            'meta_bad key' => 'x',
            'meta_empty' => '',
            'context' => 'custom',
        ]);
        $this->assertSame([
            'country' => ['include' => ['Russia', 'China'], 'exclude' => ['Iran']],
            'motive' => ['include' => ['Espionage', 'Sabotage'], 'exclude' => []],
        ], $filters);
    }
}
