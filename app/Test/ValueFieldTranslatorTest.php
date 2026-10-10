<?php
/**
 * ValueFieldTranslator against the connectionless MySQL and PostgreSQL
 * drivers: which field lists and orders it changes, and the SQL Cake renders
 * from what it hands back.
 *
 * AttributeValueValueFieldDbTest runs it through real finds.
 */

require_once __DIR__ . '/MigrationSchemaStubs.php';

use PHPUnit\Framework\TestCase;

class ValueFieldTranslatorTest extends TestCase
{
    const SORT_KEY = "(CASE WHEN `AttributeSortValue2`.`id` IS NULL"
        . " OR LENGTH(TRIM(TRAILING ' ' FROM `AttributeSortValue2`.`value`)) = 0"
        . " THEN `AttributeSortValue1`.`value`"
        . " ELSE CONCAT(`AttributeSortValue1`.`value`, '|', `AttributeSortValue2`.`value`) END)";

    /** @var MigrationTestMysqlExtended */
    private $mysql;

    /** @var MigrationTestPostgres */
    private $pgsql;

    protected function setUp(): void
    {
        require_once __DIR__ . '/../Lib/Tools/ValueFieldTranslator.php';
        $this->mysql = new MigrationTestMysqlExtended();
        $this->pgsql = new MigrationTestPostgres();
    }

    private function translator($alias = 'Attribute', $db = null)
    {
        return new ValueFieldTranslator($db ?: $this->mysql, $alias, 'attribute_values');
    }

    private function fields($fields, $alias = 'Attribute')
    {
        $translator = $this->translator($alias);
        $query = $translator->translate(['fields' => $fields]);
        return [$query['fields'], $translator->keys()];
    }

    public function testTheValueFieldIsReadAsTheIds()
    {
        list($fields, $keys) = $this->fields(['Attribute.id', 'Attribute.type', 'Attribute.value', 'Attribute.to_ids']);

        $this->assertSame(
            ['Attribute.id', 'Attribute.type', 'Attribute.value1_id', 'Attribute.value2_id', 'Attribute.to_ids'],
            $fields
        );
        $this->assertSame(['value'], $keys);
    }

    public function testBareNamesAndFieldStrings()
    {
        $this->assertSame([['Attribute.value1_id', 'Attribute.value2_id'], ['value']], $this->fields('value'));
        $this->assertSame([['Attribute.value1_id', 'Attribute.value2_id'], ['value']], $this->fields('Attribute.value'));
        $this->assertSame(
            [['id', 'Attribute.value1_id', 'Attribute.value2_id', 'type'], ['value']],
            $this->fields('id, value ,type')
        );
        $this->assertSame([['id', 'Attribute.value1_id', 'Attribute.value2_id'], ['value']], $this->fields(['id', ' value ']));
    }

    public function testTheValueColumnsNamedAlongsideReadTheIdsToo()
    {
        list($fields, $keys) = $this->fields(['Attribute.value1', 'value', 'Attribute.value2', 'Attribute.value']);

        $this->assertSame(['Attribute.value1_id', 'Attribute.value2_id'], $fields);
        $this->assertSame(['value1', 'value2', 'value'], $keys);
    }

    public function testAValueColumnWithoutTheValueFieldReadsTheIds()
    {
        $this->assertSame(
            [['Attribute.id', 'Attribute.value1_id', 'Attribute.value2_id'], ['value1']],
            $this->fields(['Attribute.id', 'Attribute.value1'])
        );
        $this->assertSame(
            [['id', 'Attribute.value1_id', 'Attribute.value2_id'], ['value1']],
            $this->fields('id, value1')
        );
        $this->assertSame(
            [['Attribute.value2_id', 'Attribute.value1_id', 'type'], ['value2']],
            $this->fields(['Attribute.value2_id', 'value2', 'type'])
        );
    }

    public function testIdsAlreadyNamedAreNotRepeated()
    {
        list($fields, $keys) = $this->fields(['Attribute.value2_id', 'Attribute.value', 'id']);

        $this->assertSame(['Attribute.value2_id', 'Attribute.value1_id', 'id'], $fields);
        $this->assertSame(['value'], $keys);
    }

    public function testEveryColumnBringsAllThreeKeys()
    {
        foreach ([['Attribute.*', 'Event.id', 'Attribute.value'], ['*', 'value']] as $list) {
            list($fields, $keys) = $this->fields($list);
            $this->assertSame(array_slice($list, 0, -1), $fields);
            $this->assertNull($keys);
        }
    }

    public function testListsWithoutAValueKeyAreLeftAlone()
    {
        $expression = $this->mysql->expression('COUNT(*) AS count');
        $lists = [
            ['Attribute.id', 'Attribute.type'],
            ['Event.value', 'ShadowAttribute.value', 'Attribute.values', 'Event.value1'],
            'COUNT(DISTINCT value) AS count',
            [$expression],
            'id, value1_id',
        ];
        foreach ($lists as $list) {
            $this->assertSame([$list, null], $this->fields($list));
        }
    }

    public function testTheAliasIsTheTranslatorsOwn()
    {
        $this->assertSame(
            [['ReferencedAttribute.value1_id', 'ReferencedAttribute.value2_id', 'Attribute.value'], ['value']],
            $this->fields(['ReferencedAttribute.value', 'Attribute.value'], 'ReferencedAttribute')
        );
        $this->assertSame(
            [['ShadowAttribute.id', 'ShadowAttribute.value1_id', 'ShadowAttribute.value2_id'], ['value']],
            $this->fields(['ShadowAttribute.id', 'ShadowAttribute.value'], 'ShadowAttribute')
        );
    }

    public function testAnOrderOnTheValueSortsByTheDictionaryText()
    {
        $query = $this->translator()->translate([
            'order' => ['Attribute.value asc', 'Attribute.id asc'],
            'joins' => [['table' => 'events', 'alias' => 'Event', 'conditions' => ['Event.id = Attribute.event_id']]],
        ]);

        $this->assertSame(' ORDER BY ' . self::SORT_KEY . ' ASC, `Attribute`.`id` asc', $this->mysql->order($query['order']));
        $this->assertCount(3, $query['joins']);
        $this->assertSame('events', $query['joins'][0]['table']);
        $this->assertSame(
            [
                'LEFT JOIN `misp`.`attribute_values` AS `AttributeSortValue1` ON (`AttributeSortValue1`.`id` = `Attribute`.`value1_id`)',
                'LEFT JOIN `misp`.`attribute_values` AS `AttributeSortValue2` ON (`AttributeSortValue2`.`id` = `Attribute`.`value2_id`)',
            ],
            [$this->mysql->buildJoinStatement($query['joins'][1]), $this->mysql->buildJoinStatement($query['joins'][2])]
        );
    }

    public function testEveryOrderShapeCakeAccepts()
    {
        $cases = [
            [['Attribute.value' => 'desc', 'Attribute.id' => 'asc'], self::SORT_KEY . ' DESC, `Attribute`.`id` asc'],
            [['Attribute.value desc, Attribute.id asc'], self::SORT_KEY . ' DESC, `Attribute`.`id` asc'],
            [[['Attribute.id DESC', 'value']], '`Attribute`.`id` DESC, ' . self::SORT_KEY . ' ASC'],
            [['value' => 'DESC'], self::SORT_KEY . ' DESC'],
            [['Attribute.value' => 'sideways'], self::SORT_KEY . ' ASC'],
            [['Attribute.value' => null], self::SORT_KEY . ' ASC'],
        ];
        foreach ($cases as list($order, $expected)) {
            $query = $this->translator()->translate(['order' => $order]);
            $this->assertSame(' ORDER BY ' . $expected, $this->mysql->order($query['order']), json_encode($order));
            $this->assertCount(2, $query['joins']);
        }
    }

    public function testOrdersWithoutTheValueFieldAreLeftAlone()
    {
        $orders = [
            [false],
            ['Attribute.id' => 'asc'],
            ['Attribute.value1 asc', 'Attribute.event_id'],
            [$this->mysql->expression('FIELD(Attribute.id, 3, 1)')],
            ['Event.value asc'],
        ];
        foreach ($orders as $order) {
            $query = ['order' => $order, 'joins' => []];
            $this->assertSame($query, $this->translator()->translate($query), json_encode($order));
        }
        $this->assertSame([], $this->translator()->translate([]));
    }

    public function testThePostgresRendering()
    {
        $query = $this->translator('ShadowAttribute', $this->pgsql)->translate(['order' => ['ShadowAttribute.value' => 'asc']]);

        $this->assertSame(
            ' ORDER BY (CASE WHEN "ShadowAttributeSortValue2"."id" IS NULL'
            . " OR LENGTH(TRIM(TRAILING ' ' FROM \"ShadowAttributeSortValue2\".\"value\")) = 0"
            . ' THEN "ShadowAttributeSortValue1"."value"'
            . " ELSE CONCAT(\"ShadowAttributeSortValue1\".\"value\", '|', \"ShadowAttributeSortValue2\".\"value\") END) ASC",
            $this->pgsql->order($query['order'])
        );
        $this->assertSame(
            'LEFT JOIN "public"."attribute_values" AS "ShadowAttributeSortValue1"'
            . ' ON ("ShadowAttributeSortValue1"."id" = "ShadowAttribute"."value1_id")',
            $this->pgsql->buildJoinStatement($query['joins'][0])
        );
    }

    public function testEachTranslationReportsItsOwnKeys()
    {
        $translator = $this->translator();
        $translator->translate(['fields' => ['value']]);
        $translator->translate(['fields' => ['id'], 'order' => ['Attribute.value']]);

        $this->assertNull($translator->keys());
    }
}
