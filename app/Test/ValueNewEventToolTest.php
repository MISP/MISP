<?php
if (!class_exists('App', false)) {
    class App
    {
        public static function uses($className, $location)
        {
        }
    }
}
if (!class_exists('Validation', false)) {
    class Validation
    {
        public static function uuid($check)
        {
            return is_string($check) && (bool)preg_match('/^[a-f0-9]{8}-[a-f0-9]{4}-[0-5][a-f0-9]{3}-[089ab][a-f0-9]{3}-[a-f0-9]{12}$/i', $check);
        }
    }
}
if (!class_exists('CakeText', false)) {
    class CakeText
    {
        public static function uuid()
        {
            $hex = bin2hex(random_bytes(16));
            return sprintf('%s-%s-4%s-a%s-%s', substr($hex, 0, 8), substr($hex, 8, 4), substr($hex, 13, 3), substr($hex, 17, 3), substr($hex, 20, 12));
        }
    }
}
require_once __DIR__ . '/../Lib/Tools/AnalystGraphDocumentTool.php';
require_once __DIR__ . '/../Lib/Tools/ValueIntelligence/ValueNewEventTool.php';

use PHPUnit\Framework\TestCase;

class ValueNewEventToolTest extends TestCase
{
    const TYPES = [
        'domain' => ['default_category' => 'Network activity', 'to_ids' => 1],
        'hostname' => ['default_category' => 'Network activity', 'to_ids' => 1],
        'text' => ['default_category' => 'Other', 'to_ids' => 0],
    ];

    const CATEGORIES = [
        'Network activity' => ['types' => ['domain', 'hostname', 'ip-dst']],
        'External analysis' => ['types' => ['domain', 'hostname', 'text']],
        'Other' => ['types' => ['text']],
    ];

    private function object(array $attributes)
    {
        return ['name' => 'dns-record', 'meta_category' => 'network', 'attributes' => $attributes];
    }

    public function testAnAttributeIsNamedAsAnalystGraphsNameItsAnswer(): void
    {
        $this->assertSame(
            AnalystGraphDocumentTool::answerUuidFor('domain', 'dns.google'),
            ValueNewEventTool::fingerprint(['type' => 'domain', 'value' => 'dns.google'], 'attribute', 'reversedns')
        );
        $this->assertSame(
            AnalystGraphDocumentTool::answerUuidFor('hostname', 'dns.google'),
            ValueNewEventTool::fingerprint(['types' => ['hostname', 'domain'], 'value' => 'dns.google'], 'element', 'dns')
        );
    }

    public function testAnObjectIsNamedByItsModuleAndContentNotItsOrder(): void
    {
        $a = ['relation' => 'queried-domain', 'type' => 'domain', 'value' => 'dns.google'];
        $b = ['relation' => 'a-record', 'type' => 'ip-dst', 'value' => '8.8.8.8'];
        $one = ValueNewEventTool::fingerprint($this->object([$a, $b]), 'object', 'reversedns');
        $this->assertSame($one, ValueNewEventTool::fingerprint($this->object([$b, $a]), 'object', 'reversedns'));
        $this->assertNotSame($one, ValueNewEventTool::fingerprint($this->object([$a, $b]), 'object', 'dns'));
    }

    public function testPicksDropWhatCannotNameARunAndRepeatNothing(): void
    {
        $fp = AnalystGraphDocumentTool::answerUuidFor('domain', 'dns.google');
        $picks = ValueNewEventTool::picks(json_encode([
            ['fp' => strtoupper($fp), 'module' => 'reversedns', 'type' => 'ip-dst'],
            ['fp' => $fp, 'module' => 'reversedns', 'type' => 'ip-dst'],
            ['fp' => 'not-a-uuid', 'module' => 'reversedns', 'type' => 'ip-dst'],
            ['fp' => $fp, 'module' => '../etc', 'type' => 'ip-dst'],
            ['fp' => $fp, 'module' => 'dns'],
            'junk',
        ]));
        $this->assertSame([['fp' => $fp, 'module' => 'reversedns', 'type' => 'ip-dst']], $picks);
        $this->assertSame([], ValueNewEventTool::picks('{not json'));
        $this->assertSame([], ValueNewEventTool::picks(null));
    }

    public function testTheIndexLeavesTheValueItselfOut(): void
    {
        $run = [
            'module' => 'reversedns',
            'attributes' => [
                ['type' => 'ip-dst', 'value' => '8.8.8.8'],
                ['type' => 'domain', 'value' => 'dns.google'],
            ],
            'objects' => [$this->object([['relation' => 'a-record', 'type' => 'ip-dst', 'value' => '8.8.8.8']])],
            'elements' => [['types' => ['text'], 'value' => '8.8.8.8']],
        ];
        $index = ValueNewEventTool::index($run, '8.8.8.8');
        $this->assertCount(2, $index);
        $this->assertSame(['attribute', 'object'], array_values(array_column($index, 'kind')));
        $this->assertArrayHasKey(AnalystGraphDocumentTool::answerUuidFor('domain', 'dns.google'), $index);
    }

    public function testCategoriesStartWithTheTypesDefault(): void
    {
        $this->assertSame(
            ['Network activity', 'External analysis'],
            ValueNewEventTool::categoriesFor('domain', self::TYPES, self::CATEGORIES)
        );
        $this->assertSame(['Other', 'External analysis'], ValueNewEventTool::categoriesFor('text', self::TYPES, self::CATEGORIES));
    }

    public function testThePayloadLinksEveryObjectToTheValue(): void
    {
        $valueUuid = CakeText::uuid();
        $object = $this->object([['relation' => 'queried-domain', 'type' => 'domain', 'value' => 'dns.google', 'category' => 'Network activity']]);
        $payload = ValueNewEventTool::payload(
            ['f1' => ['kind' => 'object', 'module' => 'reversedns', 'item' => $object]],
            ['f1' => ['relationship' => '  ']],
            $valueUuid,
            self::TYPES,
            self::CATEGORIES
        );
        $this->assertSame([], $payload['Attribute']);
        $sent = $payload['Object'][0];
        $this->assertSame('dns-record', $sent['name']);
        $this->assertSame([$valueUuid], $sent['origins']);
        $this->assertSame([['referenced_uuid' => $valueUuid, 'relationship_type' => 'related-to']], $sent['ObjectReference']);
        $this->assertSame('queried-domain', $sent['Attribute'][0]['object_relation']);
        $this->assertTrue(Validation::uuid($sent['Attribute'][0]['uuid']));
    }

    public function testThePayloadTakesOnlyEditsTheFindingAllows(): void
    {
        $findings = [
            'el' => ['kind' => 'element', 'module' => 'dns', 'item' => ['types' => ['hostname', 'text'], 'value' => 'dns.google']],
            'at' => ['kind' => 'attribute', 'module' => 'dns', 'item' => ['type' => 'domain', 'value' => 'dns.google', 'category' => 'External analysis', 'to_ids' => true]],
        ];
        $payload = ValueNewEventTool::payload($findings, [
            'el' => ['type' => 'text', 'category' => 'Network activity', 'to_ids' => true],
            'at' => ['type' => 'text', 'category' => 'Payload delivery', 'to_ids' => false],
        ], CakeText::uuid(), self::TYPES, self::CATEGORIES);
        list($element, $attribute) = $payload['Attribute'];
        $this->assertSame('text', $element['type'], 'an element may be saved as any type its module offered');
        $this->assertSame('Other', $element['category'], 'a category the type does not allow falls back to its default');
        $this->assertTrue($element['to_ids']);
        $this->assertSame('domain', $attribute['type'], 'an attribute keeps the type its module gave it');
        $this->assertSame('External analysis', $attribute['category'], 'a refused category keeps the module\'s own');
        $this->assertFalse($attribute['to_ids']);
    }
}
