<?php
require_once __DIR__ . '/../Lib/Tools/AnalystProfile/ShippedProfileTool.php';

use PHPUnit\Framework\TestCase;

class ShippedAnalystProfilesTest extends TestCase
{
    const DIRECTORY = __DIR__ . '/../files/analyst-profiles/';

    private function decode($json)
    {
        return json_decode($json);
    }

    private function shipped()
    {
        $documents = array();
        foreach (glob(self::DIRECTORY . '*.json') as $file) {
            $documents[basename($file, '.json')] = $this->decode(
                file_get_contents($file)
            );
        }
        return $documents;
    }

    private function resolvedBySlug()
    {
        $documents = $this->shipped();
        $resolved = ShippedProfileTool::resolve($documents);
        $this->assertSame(array(), $resolved['errors']);
        $bySlug = array();
        foreach ($resolved['profiles'] as $profile) {
            foreach ($documents as $slug => $document) {
                if ($document->uuid === $profile['uuid']) {
                    $bySlug[$slug] = $profile;
                }
            }
        }
        return $bySlug;
    }

    public function testMergePatchMergesObjectsAndReplacesEverythingElse()
    {
        $merged = ShippedProfileTool::mergePatch(
            $this->decode('{"a": {"x": 1, "y": 2}, "list": [1, 2], "n": 3}'),
            $this->decode('{"a": {"y": 5, "z": 6}, "list": [9], "n": null}')
        );
        $this->assertSame(
            '{"a":{"x":1,"y":5,"z":6},"list":[9]}',
            json_encode($merged)
        );
    }

    public function testMergePatchKeepsAnEmptyObjectAnObject()
    {
        $merged = ShippedProfileTool::mergePatch(
            $this->decode('{"map": {}}'),
            $this->decode('{"other": 1}')
        );
        $this->assertSame('{"map":{},"other":1}', json_encode($merged));
    }

    public function testDerivedVersionIsItsOwnPlusItsBase()
    {
        $resolved = ShippedProfileTool::resolve(array(
            'base' => $this->decode(
                '{"uuid": "b", "name": "B", "version": 21,'
                . ' "parameters": {"k": 1}}'
            ),
            'child' => $this->decode(
                '{"uuid": "c", "name": "C", "version": 9,'
                . ' "extends": "base", "parameters": {"j": 2}}'
            ),
        ));
        $child = $resolved['profiles'][1];
        $this->assertSame(30, $child['version']);
        $this->assertSame('{"k":1,"j":2}', json_encode($child['parameters']));
    }

    public function testUnknownOrChainedBaseIsRefused()
    {
        $resolved = ShippedProfileTool::resolve(array(
            'a' => $this->decode(
                '{"uuid": "a", "name": "A", "parameters": {}}'
            ),
            'b' => $this->decode(
                '{"uuid": "b", "name": "B", "extends": "a",'
                . ' "parameters": {}}'
            ),
            'c' => $this->decode(
                '{"uuid": "c", "name": "C", "extends": "b",'
                . ' "parameters": {}}'
            ),
            'd' => $this->decode(
                '{"uuid": "d", "name": "D", "extends": "nope",'
                . ' "parameters": {}}'
            ),
        ));
        $this->assertSame(array('c', 'd'), array_keys($resolved['errors']));
        $this->assertCount(2, $resolved['profiles']);
    }

    public function testEveryShippedProfileResolves()
    {
        $documents = $this->shipped();
        $this->assertArrayHasKey('default-v1', $documents);
        $this->assertCount(count($documents), $this->resolvedBySlug());
    }

    public function testPersonasKeepTheDefaultsSignalsAndThresholds()
    {
        foreach ($this->shipped() as $slug => $document) {
            if ($slug === 'default-v1') {
                continue;
            }
            $this->assertSame('default-v1', $document->extends, $slug);
            $this->assertFalse(
                property_exists($document->parameters, 'signals'),
                $slug
            );
            $this->assertFalse(
                property_exists($document->parameters, 'thresholds'),
                $slug
            );
        }
    }

    public function testPersonasOnlyAddToTheDefaultsAttributionGalaxies()
    {
        $profiles = $this->resolvedBySlug();
        $base = $profiles['default-v1']['parameters']->galaxies->attribution;
        foreach ($profiles as $slug => $profile) {
            $missing = array_diff(
                $base,
                $profile['parameters']->galaxies->attribution
            );
            $this->assertSame(array(), array_values($missing), $slug);
        }
    }
}
