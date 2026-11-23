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
require_once __DIR__ . '/../Lib/Tools/ComplexObjectQueryTool.php';

use PHPUnit\Framework\TestCase;

class ObjectQueryStubAlias
{
    public $alias;
    public $Tag;
    public $EventTag;

    public function __construct($alias)
    {
        $this->alias = $alias;
    }
}

class ObjectQueryStubEvent extends ObjectQueryStubAlias
{
    public $calls = [];

    public function __construct()
    {
        parent::__construct('Event');
        $this->EventTag = new ObjectQueryStubAlias('EventTag');
    }

    public function __call($handler, array $args)
    {
        $this->calls[] = $handler;
        $param = array_key_first($args[0]);
        return ["stub:$handler:$param" => $args[0][$param]['OR']];
    }
}

class ObjectQueryStubTag
{
    public $lookups = [];
    public $ids = [7];

    public function fetchTagIdsSimple($names)
    {
        $this->lookups[] = $names;
        return $this->ids;
    }
}

class ObjectQueryStubSharingGroup
{
    public $lookups = 0;

    public function authorizedIds($user)
    {
        $this->lookups++;
        return [3];
    }
}

class ObjectQueryStubModel extends ObjectQueryStubAlias
{
    public $Event;
    public $Object;
    public $AttributeTag;
    public $SharingGroup;

    public function __construct()
    {
        parent::__construct('Attribute');
        $this->Event = new ObjectQueryStubEvent();
        $this->Object = new ObjectQueryStubAlias('Object');
        $this->AttributeTag = new ObjectQueryStubAlias('AttributeTag');
        $this->AttributeTag->Tag = new ObjectQueryStubTag();
        $this->SharingGroup = new ObjectQueryStubSharingGroup();
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

class ComplexObjectQueryToolTest extends TestCase
{
    const USER = ['org_id' => 9, 'Role' => ['perm_site_admin' => 0]];
    const SITE_ADMIN = ['org_id' => 1, 'Role' => ['perm_site_admin' => 1]];

    private $model;

    protected function setUp(): void
    {
        $this->model = new ObjectQueryStubModel();
    }

    private function tool(array $user = self::USER): ComplexObjectQueryTool
    {
        return new ComplexObjectQueryTool($this->model, $user);
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

    /**
     * No object rule: the outer query has already proved the object visible.
     */
    private static function visibleAttribute(): array
    {
        return ['OR' => [
            ['Attribute.event_id IN (OwnEvent.id AS OwnEvent)' => ['OwnEvent.org_id' => 9]],
            ['AND' => [['OR' => [
                'Attribute.distribution' => [1, 2, 3, 5],
                'AND' => ['Attribute.distribution' => 4, 'Attribute.sharing_group_id' => [3]],
            ]]]],
        ]];
    }

    public function testObjectAndEventLeavesAreNative(): void
    {
        $c = $this->tool()->conditions(['AND' => [
            ['id' => ['>' => 5]],
            ['object_id' => ['IN' => [1, 2]]],
            ['uuid' => ['!=' => 'u']],
            ['distribution' => 4],
            ['timestamp' => ['>=' => '7d']],
            ['object_name' => ['LIKE' => 'dom%']],
            ['object_template_uuid' => 't'],
            ['event_id' => 3],
            ['orgc_id' => ['NOT IN' => [4]]],
            ['date' => ['<' => '1d']],
            ['event_timestamp' => ['<=' => 100]],
            ['published' => false],
            ['eventinfo' => ['LIKE' => '%apt%']],
        ]]);
        $this->assertSame(['AND' => [
            ['Object.id >' => 5],
            ['Object.id' => [1, 2]],
            ['NOT' => ['Object.uuid' => 'u']],
            ['Object.distribution' => 4],
            ['Object.timestamp >=' => 1700049600 - 7 * 86400],
            ['AND' => ['Object.name IS NOT NULL', ['Object.name LIKE' => 'dom%']]],
            ['AND' => ['Object.template_uuid IS NOT NULL', ['Object.template_uuid' => 't']]],
            ['Object.event_id' => 3],
            ['NOT' => ['Event.orgc_id' => [4]]],
            ['Event.date <' => '2023-11-14'],
            ['Event.timestamp <=' => 100],
            ['Event.published' => 0],
            ['stub:set_filter_eventinfo:eventinfo' => ['%apt%']],
        ]], $c);
        $this->assertSame(
            ['NOT' => ['AND' => ['Object.name IS NOT NULL', ['Object.name' => 'file']]]],
            $this->tool()->conditions(['NOT' => ['object_name' => 'file']])
        );
        $this->assertSame(
            ['NOT' => ['AND' => ['Object.name IS NOT NULL', ['Object.name LIKE' => 'dom%']]]],
            $this->tool()->conditions(['object_name' => ['NOT LIKE' => 'dom%']])
        );
        $this->assertSame(0, $this->model->SharingGroup->lookups);
    }

    public function testAttributeLeavesSelectObjectsThroughVisibleAttributes(): void
    {
        $this->assertSame(['Object.id IN (Attribute.object_id AS Attribute)' => [
            'Attribute.deleted' => 0,
            ['Attribute.object_id !=' => 0, ['stub:set_filter_type:type' => ['btc']]],
            self::visibleAttribute(),
        ]], $this->tool()->conditions(['type' => 'btc']));
        $this->assertSame(['Object.id IN (Attribute.object_id AS Attribute)' => [
            'Attribute.deleted' => 0,
            ['Attribute.object_id !=' => 0, ['Attribute.to_ids' => 1]],
        ]], $this->tool(self::SITE_ADMIN)->conditions(['to_ids' => true]));
    }

    public function testTags(): void
    {
        $eventTagged = ['Object.event_id IN (EventTag.event_id AS EventTag)' => ['EventTag.tag_id' => [7]]];
        $attributeTagged = function (array $visibility) {
            return ['AND' => [
                ['Object.event_id IN (AttributeTag.event_id AS AttributeTag)' => ['AttributeTag.tag_id' => [7]]],
                ['Object.id IN (Attribute.object_id AS Attribute)' => array_merge([
                    'Attribute.deleted' => 0,
                    [
                        'Attribute.object_id = Object.id',
                        ['Attribute.id IN (AttributeTag.attribute_id AS AttributeTag)' => [
                            'AttributeTag.tag_id' => [7],
                            'AttributeTag.attribute_id = Attribute.id',
                        ]],
                    ],
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

        $c = $tool->conditions(['AND' => [['type' => 'btc'], ['tags' => ['NOT IN' => ['a', 'b']]]]]);
        $this->assertSame(['NOT' => $eventTagged], $c['AND'][1]);
        $this->assertSame([7], $tool->blockedTagIds());
        $this->assertSame([['x'], ['tlp:%'], ['a', 'b']], $this->model->AttributeTag->Tag->lookups);

        $c = $tool->conditions(['AND' => [['type' => 'btc'], ['tags' => ['NOT LIKE' => 'tlp:%']]]]);
        $this->assertSame(['NOT' => $eventTagged], $c['AND'][1]);
        $this->assertSame([7], $tool->blockedTagIds());
    }

    public function testAttributeLeavesCannotBeNegated(): void
    {
        foreach ([['type' => ['!=' => 'btc']], ['comment' => ['NOT IN' => ['a']]], ['value' => ['NOT LIKE' => 'a%']], ['to_ids' => ['!=' => true]]] as $query) {
            $errors = $this->errors($query);
            $this->assertSame('unknown_operator', $errors[0]['code'], json_encode($query));
            $this->assertSame('attribute fields cannot be negated when searching objects', $errors[0]['message']);
        }
        foreach ([
            'query.NOT.value' => ['NOT' => ['value' => 'x']],
            'query.NOT.OR[1].tags' => ['NOT' => ['OR' => [['id' => 1], ['tags' => 'x']]]],
            'query.OR[1].tags' => ['OR' => [['id' => 1], ['tags' => ['!=' => 'x']]]],
            'query.OR[0].tags' => ['OR' => [['tags' => ['NOT LIKE' => 'x%']], ['id' => 1]]],
        ] as $path => $query) {
            $errors = $this->errors($query);
            $this->assertSame([$path, 'bad_shape'], [$errors[0]['path'], $errors[0]['code']], $path);
            $this->assertStringContainsString('searching objects', $errors[0]['message']);
        }
        foreach ([
            ['NOT' => ['OR' => [['object_name' => 'file'], ['orgc_id' => 2], ['date' => '1d']]]],
            ['AND' => [['tags' => ['!=' => 'x']], ['OR' => [['type' => 'a'], ['id' => 1]]]]],
            ['AND' => [['tags' => ['NOT LIKE' => 'x%']], ['OR' => [['type' => 'a'], ['object_name' => ['NOT LIKE' => 'f%']]]]]],
        ] as $query) {
            $this->tool()->conditions($query);
        }
    }

    public function testValidationDoesNoDatabaseWork(): void
    {
        $this->errors(['AND' => [['type' => 'a'], ['tags' => 'x'], ['id' => 'bad']]]);
        $this->assertSame([], $this->model->Event->calls);
        $this->assertSame([], $this->model->AttributeTag->Tag->lookups);
        $this->assertSame(0, $this->model->SharingGroup->lookups);
    }

    public function testObjectsCannotBeSorted(): void
    {
        $this->expectException(ComplexQueryException::class);
        $this->tool()->validateOrder('id', []);
    }

    public function testDescribeListsTheObjectFields(): void
    {
        $d = $this->tool()->discovery('objects', '/objects/restSearch', [], 'Object');
        $table = $d['tables']['objects'];
        $this->assertSame(array_keys(ComplexObjectQueryTool::FIELDS), array_keys($table['fields']));
        $this->assertSame([], $table['sortable']);
        $this->assertSame(['=', '!=', 'IN', 'NOT IN', 'LIKE', 'NOT LIKE'], $table['fields']['object_name']['operators']);
        $this->assertSame(['=', '!=', 'IN', 'NOT IN', 'LIKE', 'NOT LIKE'], $table['fields']['tags']['operators']);
        $this->assertSame(['=', 'IN', 'LIKE'], $table['fields']['value']['operators']);
        $this->assertSame(['object'], $table['fields']['id']['level']);
        $this->assertSame(['event'], $table['fields']['orgc_id']['level']);
        $this->assertSame(['event', 'attribute'], $table['fields']['tags']['level']);
    }
}
