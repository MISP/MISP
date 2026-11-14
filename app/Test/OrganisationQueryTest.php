<?php
/**
 * The `query` fields of /organisations/restSearch (Organisation::QUERY_FIELDS)
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

require_once __DIR__ . '/../Model/Organisation.php';

use PHPUnit\Framework\TestCase;

class OrganisationQueryStub extends Organisation
{
    public function __construct()
    {
    }

    public function resolveTimeDelta($delta)
    {
        // 2023-11-15 12:00 UTC
        return 1700049600 - 86400 * (int)$delta;
    }
}

class OrganisationQueryTest extends TestCase
{
    private function tool(): ComplexQueryTool
    {
        return new ComplexQueryTool(new OrganisationQueryStub(), [], Organisation::QUERY_FIELDS);
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

    public function testNameIsComparedInLowerCase(): void
    {
        $tool = $this->tool();
        $this->assertSame(['LOWER(Organisation.name)' => 'circl'], $tool->conditions(['name' => 'CIRCL']));
        $this->assertSame(['LOWER(Organisation.name) LIKE' => '%bank%'], $tool->conditions(['name' => ['LIKE' => '%Bank%']]));
    }

    public function testUuidIsExactWithTheValueLowercased(): void
    {
        $this->assertSame(['Organisation.uuid' => 'abc-def'], $this->tool()->conditions(['uuid' => 'ABC-DEF']));
        $this->assertSame(['unknown_operator'], array_column($this->errors(['uuid' => ['LIKE' => 'ab%']]), 'code'));
    }

    public function testOtherColumnsAreNative(): void
    {
        $tool = $this->tool();
        $this->assertSame(['Organisation.sector LIKE' => 'gov%'], $tool->conditions(['sector' => ['LIKE' => 'gov%']]));
        $this->assertSame(['Organisation.local' => 0], $tool->conditions(['local' => false]));
        $this->assertSame(['Organisation.id >' => 500], $tool->conditions(['id' => ['>' => 500]]));
        $this->assertSame(
            ['NOT' => ['AND' => ['Organisation.contacts IS NOT NULL', ['Organisation.contacts LIKE' => '%@%']]]],
            $tool->conditions(['contacts' => ['NOT LIKE' => '%@%']])
        );
    }

    public function testDatesAreInTheServersTimeZone(): void
    {
        $zone = date_default_timezone_get();
        date_default_timezone_set('Europe/Luxembourg');
        try {
            $this->assertSame(['Organisation.date_modified >' => '2023-11-08 13:00:00'], $this->tool()->conditions(['date_modified' => ['>' => '7d']]));
            $this->assertSame(['Organisation.date_created' => '2021-04-26'], $this->tool()->conditions(['date_created' => '2021-04-26']));
        } finally {
            date_default_timezone_set($zone);
        }
    }

    public function testHiddenAndComputedFieldsAreUnknown(): void
    {
        foreach (['created_by', 'created_by_email', 'user_count', 'restricted_to_domain', 'org', 'Organisation.name', 'meta.x'] as $field) {
            $error = $this->errors([$field => 1])[0];
            $this->assertSame(['unknown_field', 'query.<unknown>'], [$error['code'], $error['path']], $field);
        }
    }

    public function testOrderIsTheWhitelist(): void
    {
        $this->tool()->validateOrder(['name desc', 'Organisation.date_modified'], Organisation::REST_SEARCH_ORDER_FIELDS, 'Organisation');
        foreach (['user_count', 'created_by', 'sector', 'uuid', 'LOWER(name)', 'id sideways'] as $order) {
            try {
                $this->tool()->validateOrder($order, Organisation::REST_SEARCH_ORDER_FIELDS, 'Organisation');
                $this->fail("accepted $order");
            } catch (ComplexQueryException $e) {
                $this->assertSame('order[0]', $e->errors[0]['path'], $order);
            }
        }
    }

    public function testDiscoveryListsEveryField(): void
    {
        $d = $this->tool()->discovery('organisations', '/organisations/restSearch', Organisation::REST_SEARCH_ORDER_FIELDS, 'Organisation');
        $table = $d['tables']['organisations'];
        $this->assertSame(array_keys(Organisation::QUERY_FIELDS), array_keys($table['fields']));
        $this->assertSame(['id', 'name', 'date_created', 'date_modified'], $table['sortable']);
        $this->assertSame('datetime', $table['fields']['date_created']['type']);
        $this->assertSame(['organisation'], $table['fields']['name']['level']);
    }
}
