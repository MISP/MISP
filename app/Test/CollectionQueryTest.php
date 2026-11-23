<?php
/**
 * The `query` fields of /collections/restSearch (Collection::QUERY_FIELDS)
 * compiled by ComplexQueryTool. Pure PHPUnit, no CakePHP bootstrap, no DB.
 */

require_once __DIR__ . '/../Vendor/autoload.php';
require_once __DIR__ . '/../Lib/Tools/ComplexQueryTool.php';

if (!class_exists('App', false)) {
    class App
    {
        public static function uses($class, $package)
        {
        }
    }
}
if (!class_exists('AppModel', false)) {
    class AppModel
    {
    }
}

require_once __DIR__ . '/../Model/Collection.php';

use PHPUnit\Framework\TestCase;

class CollectionQueryStubAssociation
{
    public $alias;

    public function __construct($alias)
    {
        $this->alias = $alias;
    }
}

class CollectionQueryStub extends Collection
{
    public function __construct()
    {
        $this->Orgc = new CollectionQueryStubAssociation('Orgc');
        $this->CollectionElement = new CollectionQueryStubAssociation('CollectionElement');
    }

    public function subQueryGenerator($model, array $options, $lookupKey)
    {
        return ["$lookupKey IN ({$options['fields'][0]})" => $options['conditions']];
    }

    public function resolveTimeDelta($delta)
    {
        // 2023-11-15 12:00 UTC
        return 1700049600 - 86400 * (int)$delta;
    }
}

class CollectionQueryTest extends TestCase
{
    private function tool(array $fields = Collection::QUERY_FIELDS): ComplexQueryTool
    {
        return new ComplexQueryTool(new CollectionQueryStub(), [], $fields);
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

    public function testOwnColumnsAreNative(): void
    {
        $tool = $this->tool();
        $this->assertSame(['Collection.distribution' => [0, 4]], $tool->conditions(['distribution' => ['IN' => [0, 4]]]));
        $this->assertSame(['Collection.locked' => 1], $tool->conditions(['locked' => true]));
        $this->assertSame(['Collection.name LIKE' => '%apt%'], $tool->conditions(['name' => ['LIKE' => '%apt%']]));
        $this->assertSame(['Collection.user_id' => 5], $tool->conditions(['user_id' => 5]));
        $this->assertSame(['unknown_operator'], array_column($this->errors(['uuid' => ['LIKE' => 'ab%']]), 'code'));
    }

    public function testDatetimesAreInTheServersTimeZone(): void
    {
        $zone = date_default_timezone_get();
        date_default_timezone_set('Europe/Luxembourg');
        try {
            $this->assertSame(['Collection.modified >' => '2023-11-08 13:00:00'], $this->tool()->conditions(['modified' => ['>' => '7d']]));
            $this->assertSame(['Collection.created <=' => '2023-11-15 13:00:00'], $this->tool()->conditions(['created' => ['<=' => 1700049600]]));
            $this->assertSame(['Collection.created' => '2024-02-29'], $this->tool()->conditions(['created' => '2024-02-29']));
            $utc = $this->tool(['modified' => ['kind' => 'datetime', 'column' => 'Note.modified']]);
            $this->assertSame(['Note.modified >' => '2023-11-08 12:00:00'], $utc->conditions(['modified' => ['>' => '7d']]));
        } finally {
            date_default_timezone_set($zone);
        }
    }

    public function testOrgIsTheCreatorByNameOrUuid(): void
    {
        $this->assertSame(
            ['Collection.orgc_id IN (Orgc.id)' => [
                ['OR' => [['LOWER(Orgc.name)' => 'circl'], ['LOWER(Orgc.uuid)' => 'circl']]],
            ]],
            $this->tool()->conditions(['org' => 'CIRCL'])
        );
        $this->assertSame(['unknown_operator'], array_column($this->errors(['org' => ['LIKE' => '%CIRCL%']]), 'code'));
    }

    public function testElementFieldsMatchAnyElement(): void
    {
        $tool = $this->tool();
        $this->assertSame(
            ['Collection.id IN (CollectionElement.collection_id)' => [['CollectionElement.element_uuid' => 'x']]],
            $tool->conditions(['element_uuid' => 'x'])
        );
        $this->assertSame(
            ['Collection.id IN (CollectionElement.collection_id)' => [['CollectionElement.element_sha256' => 'abcdef']]],
            $tool->conditions(['element_sha256' => 'ABCDEF'])
        );
        // no element matches: empty collections included
        $this->assertSame(
            ['NOT' => ['Collection.id IN (CollectionElement.collection_id)' => [['CollectionElement.description LIKE' => '%apt%']]]],
            $tool->conditions(['element_description' => ['NOT LIKE' => '%apt%']])
        );
        $this->assertSame(['unknown_operator'], array_column($this->errors(['element_type' => ['LIKE' => 'Ev%']]), 'code'));
    }

    public function testDescriptionNegationAlsoMatchesNull(): void
    {
        $this->assertSame(
            ['NOT' => ['AND' => ['Collection.description IS NOT NULL', ['Collection.description' => 'x']]]],
            $this->tool()->conditions(['description' => ['!=' => 'x']])
        );
    }

    public function testComputedAndOtherRecordsFieldsAreUnknown(): void
    {
        foreach (['sharing_group_id', 'element_count', 'element_id', 'tags', 'eventinfo', 'info', 'Collection.id', 'Orgc.name', 'meta.x'] as $field) {
            $error = $this->errors([$field => 1])[0];
            $this->assertSame(['unknown_field', 'query.<unknown>'], [$error['code'], $error['path']], $field);
        }
    }

    public function testOrderIsTheWhitelist(): void
    {
        $this->tool()->validateOrder(['name desc', 'Collection.modified'], Collection::REST_SEARCH_ORDER_FIELDS, 'Collection');
        foreach (['element_count', 'user_id', 'uuid', 'org', 'Orgc.name', 'id sideways'] as $order) {
            try {
                $this->tool()->validateOrder($order, Collection::REST_SEARCH_ORDER_FIELDS, 'Collection');
                $this->fail("accepted $order");
            } catch (ComplexQueryException $e) {
                $this->assertSame('order[0]', $e->errors[0]['path'], $order);
            }
        }
    }

    public function testDiscoveryListsEveryField(): void
    {
        $d = $this->tool()->discovery('collections', '/collections/restSearch', Collection::REST_SEARCH_ORDER_FIELDS, 'Collection');
        $table = $d['tables']['collections'];
        $this->assertSame(array_keys(Collection::QUERY_FIELDS), array_keys($table['fields']));
        $this->assertSame(['id', 'name', 'type', 'created', 'modified', 'distribution'], $table['sortable']);
        $this->assertSame('datetime', $table['fields']['modified']['type']);
        $this->assertSame(['collection_element'], $table['fields']['element_uuid']['level']);
        $this->assertSame(['=', '!=', 'IN', 'NOT IN'], $table['fields']['element_type']['operators']);
    }
}
