<?php
require_once __DIR__ . '/../Lib/Tools/ComplexQueryTool.php';
if (!class_exists('App')) {
    class App
    {
        public static function uses($className, $location)
        {
        }
    }
}
require_once __DIR__ . '/../Lib/Tools/ComplexEventQueryTool.php';

use PHPUnit\Framework\TestCase;

class EventQueryStubAlias
{
    public $alias;
    public $Tag;

    public function __construct($alias)
    {
        $this->alias = $alias;
    }
}

class EventQueryStubEvent extends EventQueryStubAlias
{
    public $EventTag;
    public $calls = [];

    public function __construct()
    {
        parent::__construct('Event');
        $this->EventTag = new EventQueryStubAlias('EventTag');
    }

    public function __call($handler, array $args)
    {
        $this->calls[] = $handler;
        $param = array_key_first($args[0]);
        return ["stub:$handler:$param" => $args[0][$param]['OR']];
    }
}

class EventQueryStubTag
{
    public $lookups = [];
    public $ids = [7];

    public function fetchTagIdsSimple($names)
    {
        $this->lookups[] = $names;
        return $this->ids;
    }
}

class EventQueryStubSharingGroup
{
    public $lookups = 0;

    public function authorizedIds($user)
    {
        $this->lookups++;
        return [3];
    }
}

class EventQueryStubModel extends EventQueryStubAlias
{
    public $Event;
    public $Object;
    public $AttributeTag;
    public $SharingGroup;

    public function __construct()
    {
        parent::__construct('Attribute');
        $this->Event = new EventQueryStubEvent();
        $this->Object = new EventQueryStubAlias('Object');
        $this->AttributeTag = new EventQueryStubAlias('AttributeTag');
        $this->AttributeTag->Tag = new EventQueryStubTag();
        $this->SharingGroup = new EventQueryStubSharingGroup();
    }

    public function subQueryGenerator($model, array $options, $lookupKey)
    {
        return ["$lookupKey IN ({$options['fields'][0]} AS {$options['alias']})" => $options['conditions']];
    }

    public function resolveTimeDelta($delta)
    {
        // 2023-11-15 12:00 UTC
        return 1700049600 - 86400 * (int)$delta;
    }
}

class ComplexEventQueryToolTest extends TestCase
{
    const USER = ['org_id' => 9, 'Role' => ['perm_site_admin' => 0]];
    const SITE_ADMIN = ['org_id' => 1, 'Role' => ['perm_site_admin' => 1]];

    private $model;

    protected function setUp(): void
    {
        $this->model = new EventQueryStubModel();
    }

    private function tool(array $user = self::USER): ComplexEventQueryTool
    {
        return new ComplexEventQueryTool($this->model, $user);
    }

    private function errors($query): array
    {
        try {
            $this->tool()->conditions($query);
        } catch (ComplexQueryException $e) {
            return $e->errors;
        }
        $this->fail('the query was accepted');
    }

    private static function distribution($alias): array
    {
        return ['OR' => [
            "$alias.distribution" => [1, 2, 3, 5],
            'AND' => ["$alias.distribution" => 4, "$alias.sharing_group_id" => [3]],
        ]];
    }

    private static function ownEvent($alias): array
    {
        return ["$alias.event_id IN (OwnEvent.id AS OwnEvent)" => ['OwnEvent.org_id' => 9]];
    }

    private static function visibleAttribute(): array
    {
        return ['OR' => [
            self::ownEvent('Attribute'),
            ['AND' => [
                self::distribution('Attribute'),
                ['OR' => [
                    'Attribute.object_id' => 0,
                    ['Attribute.object_id IN (Object.id AS Object)' => self::distribution('Object')],
                ]],
            ]],
        ]];
    }

    public function testEventLeavesAreNative(): void
    {
        $c = $this->tool()->conditions(['AND' => [
            ['id' => ['>' => 5]],
            ['event_id' => ['IN' => [1, 2]]],
            ['published' => true],
            ['distribution' => ['!=' => 0]],
            ['NOT' => ['orgc_id' => 4]],
            ['eventinfo' => ['LIKE' => '%apt%']],
            ['event_timestamp' => ['>=' => '7d']],
        ]]);
        $this->assertSame(['AND' => [
            ['Event.id >' => 5],
            ['Event.id' => [1, 2]],
            ['Event.published' => 1],
            ['NOT' => ['Event.distribution' => 0]],
            ['NOT' => ['Event.orgc_id' => 4]],
            ['stub:set_filter_eventinfo:eventinfo' => ['%apt%']],
            ['Event.timestamp >=' => 1700049600 - 7 * 86400],
        ]], $c);
        $this->assertSame(0, $this->model->SharingGroup->lookups);
    }

    public function testDates(): void
    {
        $this->assertSame(['Event.date >=' => '2024-02-29'], $this->tool()->conditions(['date' => ['>=' => '2024-02-29']]));
        $this->assertSame(['Event.date >=' => '2023-11-08'], $this->tool()->conditions(['date' => ['>=' => '7d']]));
        $this->assertSame(['Event.date' => ['2023-11-14', '2020-01-01']], $this->tool()->conditions(['date' => ['IN' => ['1d', '2020-01-01']]]));
        foreach (['2026-02-30', '2026-1-01', '7h', '7', 20260101, '2026-01-01 00:00', ''] as $bad) {
            $this->assertSame(['bad_type'], array_column($this->errors(['date' => $bad]), 'code'), json_encode($bad));
        }
    }

    public function testAttributeLeavesSelectEventsThroughVisibleAttributes(): void
    {
        $c = $this->tool()->conditions(['type' => 'btc']);
        $this->assertSame(['Event.id IN (Attribute.event_id AS Attribute)' => [
            'Attribute.deleted' => 0,
            ['stub:set_filter_type:type' => ['btc']],
            self::visibleAttribute(),
        ]], $c);
        $this->assertSame(['Event.id IN (Attribute.event_id AS Attribute)' => [
            'Attribute.deleted' => 0,
            ['Attribute.to_ids' => 1],
        ]], $this->tool(self::SITE_ADMIN)->conditions(['to_ids' => true]));
    }

    public function testObjectLeavesSelectEventsThroughVisibleObjects(): void
    {
        $c = $this->tool()->conditions(['object_name' => ['IN' => ['file', 'domain-ip']]]);
        $this->assertSame(['Event.id IN (Object.event_id AS Object)' => [
            'Object.deleted' => 0,
            ['Object.name' => ['file', 'domain-ip']],
            ['OR' => [self::ownEvent('Object'), ['AND' => [self::distribution('Object')]]]],
        ]], $c);
    }

    public function testTags(): void
    {
        $eventTagged = ['Event.id IN (EventTag.event_id AS EventTag)' => ['EventTag.tag_id' => [7]]];
        $attributeTagged = function (array $visibility) {
            return ['Event.id IN (AttributeTag.event_id AS AttributeTag)' => [
                'AttributeTag.tag_id' => [7],
                ['AttributeTag.attribute_id IN (Attribute.id AS Attribute)' => array_merge([
                    'Attribute.deleted' => 0,
                    ['Attribute.id = AttributeTag.attribute_id'],
                ], $visibility)],
            ]];
        };
        $this->assertSame(
            ['OR' => [$eventTagged, $attributeTagged([self::visibleAttribute()])]],
            $this->tool()->conditions(['tags' => 'x'])
        );
        $tool = $this->tool(self::SITE_ADMIN);
        $this->assertSame(['OR' => [$eventTagged, $attributeTagged([])]], $tool->conditions(['tags' => ['LIKE' => 'tlp:%']]));
        $this->assertSame([], $tool->blockedTagIds());

        $c = $tool->conditions(['AND' => [['type' => 'btc'], ['tags' => ['NOT IN' => ['a', 'b']]], ['tags' => ['!=' => 'c']]]]);
        $this->assertSame(['NOT' => $eventTagged], $c['AND'][1]);
        $this->assertSame([7], $tool->blockedTagIds());
        $this->assertSame([['x'], ['tlp:%'], ['a', 'b'], ['c']], $this->model->AttributeTag->Tag->lookups);

        $this->model->AttributeTag->Tag->ids = [-1];
        $this->assertSame(
            ['NOT' => ['Event.id IN (EventTag.event_id AS EventTag)' => ['EventTag.tag_id' => [-1]]]],
            $tool->conditions(['tags' => ['!=' => 'missing']])
        );
        $this->assertSame([], $tool->blockedTagIds());
    }

    public function testElementLeavesCannotBeNegated(): void
    {
        foreach ([['type' => ['!=' => 'btc']], ['value' => ['NOT IN' => ['a']]], ['to_ids' => ['!=' => true]]] as $query) {
            $errors = $this->errors($query);
            $this->assertSame('unknown_operator', $errors[0]['code'], json_encode($query));
            $this->assertStringContainsString('cannot be negated', $errors[0]['message']);
        }
        $this->assertSame('operator not allowed for this field', $this->errors(['object_template_uuid' => ['LIKE' => 'f%']])[0]['message']);
        $this->assertSame(['Event.id IN (Object.event_id AS Object)' => [
            'Object.deleted' => 0,
            ['Object.name LIKE' => 'f%'],
            ['OR' => [self::ownEvent('Object'), ['AND' => [self::distribution('Object')]]]],
        ]], $this->tool()->conditions(['object_name' => ['LIKE' => 'f%']]));

        $cases = [
            'query.NOT.type' => ['NOT' => ['type' => 'btc']],
            'query.NOT.AND[1].tags' => ['NOT' => ['AND' => [['id' => 1], ['tags' => 'x']]]],
            'query.OR[1].tags' => ['OR' => [['id' => 1], ['tags' => ['!=' => 'x']]]],
            'query.AND[0].OR[0].tags' => ['AND' => [['OR' => [['tags' => ['NOT IN' => ['x']]]]]]],
        ];
        foreach ($cases as $path => $query) {
            $this->assertSame([['path' => $path, 'code' => 'bad_shape']], array_map(function ($e) {
                return ['path' => $e['path'], 'code' => $e['code']];
            }, $this->errors($query)), $path);
        }
        foreach ([
            ['tags' => ['!=' => 'x']],
            ['AND' => [['id' => 1], ['AND' => [['tags' => ['!=' => 'x']]]]]],
            ['OR' => [['tags' => 'x'], ['NOT' => ['eventinfo' => 'y']]]],
            ['NOT' => ['OR' => [['id' => 1], ['date' => '1d']]]],
        ] as $query) {
            $this->tool()->conditions($query);
        }
    }

    public function testValidationDoesNoDatabaseWork(): void
    {
        $this->errors(['AND' => [['type' => 'a'], ['tags' => 'x'], ['id' => 'bad']]]);
        $this->errors(['AND' => [['type' => 'a'], ['OR' => [['tags' => ['!=' => 'x']]]]]]);
        $this->assertSame([], $this->model->Event->calls);
        $this->assertSame([], $this->model->AttributeTag->Tag->lookups);
        $this->assertSame(0, $this->model->SharingGroup->lookups);
    }

    public function testOrderDefaultsToTheEventModel(): void
    {
        $allowed = ['Event' => ['id', 'timestamp']];
        $this->tool()->validateOrder('timestamp desc', $allowed, 'Event');
        $this->expectException(ComplexQueryException::class);
        $this->tool()->validateOrder('Attribute.id', $allowed, 'Event');
    }

    public function testDescribeListsTheEventFields(): void
    {
        $d = $this->tool()->describe();
        $this->assertSame(array_keys(ComplexEventQueryTool::FIELDS), array_keys($d['fields']));
        $this->assertSame('date', $d['fields']['date']['type']);
        $this->assertSame(['=', 'IN', 'LIKE'], $d['fields']['type']['operators']);
        $this->assertSame(['=', '!=', 'IN', 'NOT IN', 'LIKE'], $d['fields']['tags']['operators']);
        $this->assertArrayNotHasKey('info', $d['fields']);
        $this->assertSame(['event'], $d['fields']['eventinfo']['level']);
        $this->assertSame(['event', 'attribute'], $d['fields']['tags']['level']);
        $this->assertSame(['attribute'], $d['fields']['value']['level']);
        $this->assertSame(['object'], $d['fields']['object_name']['level']);
        $sortable = $this->tool()->discovery('events', '/events/restSearch', ['Event' => ['id', 'info']], 'Event')['tables']['events']['sortable'];
        $this->assertSame(['id', 'info'], $sortable);
    }
}
