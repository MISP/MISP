<?php
/**
 * The `query` fields of /tags/restSearch (Tag::QUERY_FIELDS) compiled by
 * ComplexQueryTool. Pure PHPUnit, no CakePHP bootstrap, no DB.
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

require_once __DIR__ . '/../Model/Tag.php';

use PHPUnit\Framework\TestCase;

class TagQueryStub extends Tag
{
    public function __construct()
    {
    }
}

class TagQueryTest extends TestCase
{
    private function tool(): ComplexQueryTool
    {
        return new ComplexQueryTool(new TagQueryStub(), [], Tag::QUERY_FIELDS);
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

    public function testColumnsAreNative(): void
    {
        $tool = $this->tool();
        $this->assertSame(['Tag.name LIKE' => 'tlp:%'], $tool->conditions(['name' => ['LIKE' => 'tlp:%']]));
        $this->assertSame(['Tag.name' => ['tlp:red', 'tlp:amber']], $tool->conditions(['name' => ['IN' => ['tlp:red', 'tlp:amber']]]));
        $this->assertSame(['Tag.hide_tag' => 1], $tool->conditions(['hide_tag' => true]));
        $this->assertSame(['Tag.is_galaxy' => 0], $tool->conditions(['is_galaxy' => false]));
        $this->assertSame(['Tag.org_id >' => 0], $tool->conditions(['org_id' => ['>' => 0]]));
        $this->assertSame(['Tag.user_id' => 5], $tool->conditions(['user_id' => 5]));
    }

    public function testColourIsExactInAnyCase(): void
    {
        $this->assertSame(['LOWER(Tag.colour)' => '#ffc000'], $this->tool()->conditions(['colour' => '#FFC000']));
        $this->assertSame(['unknown_operator'], array_column($this->errors(['colour' => ['LIKE' => '#ff%']]), 'code'));
    }

    public function testNumericalValueNegationAlsoMatchesNull(): void
    {
        $tool = $this->tool();
        $this->assertSame(
            ['AND' => ['Tag.numerical_value IS NOT NULL', ['Tag.numerical_value >=' => 75]]],
            $tool->conditions(['numerical_value' => ['>=' => 75]])
        );
        $this->assertSame(
            ['NOT' => ['AND' => ['Tag.numerical_value IS NOT NULL', ['Tag.numerical_value' => 100]]]],
            $tool->conditions(['numerical_value' => ['!=' => 100]])
        );
    }

    public function testComputedAndOtherRecordsFieldsAreUnknown(): void
    {
        foreach (['count', 'attribute_count', 'favourite', 'Taxonomy', 'org', 'Organisation.name', 'Tag.name', 'original_numerical_value', 'meta.x'] as $field) {
            $error = $this->errors([$field => 1])[0];
            $this->assertSame(['unknown_field', 'query.<unknown>'], [$error['code'], $error['path']], $field);
        }
    }

    public function testOrderIsTheWhitelist(): void
    {
        $this->tool()->validateOrder(['numerical_value desc', 'Tag.name'], Tag::REST_SEARCH_ORDER_FIELDS, 'Tag');
        foreach (['count', 'attribute_count', 'colour', 'favourite', 'Organisation.name', 'id sideways'] as $order) {
            try {
                $this->tool()->validateOrder($order, Tag::REST_SEARCH_ORDER_FIELDS, 'Tag');
                $this->fail("accepted $order");
            } catch (ComplexQueryException $e) {
                $this->assertSame('order[0]', $e->errors[0]['path'], $order);
            }
        }
    }

    public function testDiscoveryListsEveryField(): void
    {
        $d = $this->tool()->discovery('tags', '/tags/restSearch', Tag::REST_SEARCH_ORDER_FIELDS, 'Tag');
        $table = $d['tables']['tags'];
        $this->assertSame(array_keys(Tag::QUERY_FIELDS), array_keys($table['fields']));
        $this->assertSame(['id', 'name', 'numerical_value'], $table['sortable']);
        $this->assertSame('bool', $table['fields']['local_only']['type']);
        $this->assertSame(['=', '!=', 'IN', 'NOT IN'], $table['fields']['colour']['operators']);
    }
}
