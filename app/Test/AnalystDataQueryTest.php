<?php
/**
 * The `query` fields of /analyst_data/restSearch/<Type> (AnalystData::queryFields())
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
if (!class_exists('Inflector', false)) {
    class Inflector
    {
        public static function underscore($word)
        {
            return strtolower(preg_replace('/(?<=\w)([A-Z])/', '_$1', $word));
        }
    }
}

require_once __DIR__ . '/../Model/AnalystData.php';
require_once __DIR__ . '/../Model/Note.php';
require_once __DIR__ . '/../Model/Opinion.php';
require_once __DIR__ . '/../Model/Relationship.php';

use PHPUnit\Framework\TestCase;

class AnalystDataQueryStubOrganisation
{
    public $alias = 'Organisation';
}

trait AnalystDataQueryStub
{
    public function __construct()
    {
        $this->alias = $this->current_type;
        $this->Orgc = new AnalystDataQueryStubOrganisation();
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

class AnalystDataQueryStubNote extends Note
{
    use AnalystDataQueryStub;
}

class AnalystDataQueryStubOpinion extends Opinion
{
    use AnalystDataQueryStub;
}

class AnalystDataQueryStubRelationship extends Relationship
{
    use AnalystDataQueryStub;
}

class AnalystDataQueryTest extends TestCase
{
    private function tool($type = 'Note'): ComplexQueryTool
    {
        $class = 'AnalystDataQueryStub' . $type;
        $model = new $class();
        return new ComplexQueryTool($model, [], $model->queryFields());
    }

    private function errors($query, $type = 'Note'): array
    {
        try {
            $this->tool($type)->conditions($query);
        } catch (ComplexQueryException $e) {
            return $e->errors;
        }
        $this->fail('the query was accepted');
    }

    public function testCommonColumnsAreNativeOnEachType(): void
    {
        $this->assertSame(['Note.distribution' => [0, 4]], $this->tool()->conditions(['distribution' => ['IN' => [0, 4]]]));
        $this->assertSame(['Opinion.locked' => 1], $this->tool('Opinion')->conditions(['locked' => true]));
        $this->assertSame(['Relationship.object_type' => 'Event'], $this->tool('Relationship')->conditions(['object_type' => 'Event']));
        $this->assertSame(['Note.orgc_uuid' => 'x'], $this->tool()->conditions(['orgc_uuid' => 'x']));
    }

    public function testDatetimesAreUtc(): void
    {
        $tool = $this->tool();
        $this->assertSame(['Note.modified >' => '2023-11-08 12:00:00'], $tool->conditions(['modified' => ['>' => '7d']]));
        $this->assertSame(['Note.created <=' => '2023-11-15 12:00:00'], $tool->conditions(['created' => ['<=' => 1700049600]]));
        $this->assertSame(['Note.created' => '2024-02-29'], $tool->conditions(['created' => '2024-02-29']));
        $this->assertSame(['Note.created >' => '2024-02-29 23:59:59'], $tool->conditions(['created' => ['>' => '2024-02-29 23:59:59']]));
        foreach (['2023-02-30', '2024-02-29T10:00:00', '2024-02-29 24:00:00', '7w', true, 1.5] as $bad) {
            $this->assertSame(['bad_type'], array_column($this->errors(['modified' => $bad]), 'code'), json_encode($bad));
        }
    }

    public function testOrgIsTheCreatorByNameOrUuid(): void
    {
        $this->assertSame(
            ['Opinion.orgc_uuid IN (Organisation.uuid)' => [
                ['OR' => [['LOWER(Organisation.name)' => 'circl'], ['LOWER(Organisation.uuid)' => 'circl']]],
            ]],
            $this->tool('Opinion')->conditions(['org' => 'CIRCL'])
        );
        $this->assertSame(['unknown_operator'], array_column($this->errors(['org' => ['LIKE' => '%CIRCL%']]), 'code'));
    }

    public function testSha256ValuesAreLowercasedNotTheColumn(): void
    {
        $this->assertSame(
            ['AND' => ['Relationship.related_object_sha256 IS NOT NULL', ['Relationship.related_object_sha256' => 'abcdef']]],
            $this->tool('Relationship')->conditions(['related_object_sha256' => 'ABCDEF'])
        );
    }

    public function testNegationAlsoMatchesNull(): void
    {
        $this->assertSame(
            ['NOT' => ['AND' => ['Note.note IS NOT NULL', ['Note.note LIKE' => '%apt%']]]],
            $this->tool()->conditions(['note' => ['NOT LIKE' => '%apt%']])
        );
        $this->assertSame(
            ['NOT' => ['AND' => ['Opinion.opinion IS NOT NULL', ['Opinion.opinion' => [0, 100]]]]],
            $this->tool('Opinion')->conditions(['opinion' => ['NOT IN' => [0, 100]]])
        );
    }

    public function testEachTypeHasOnlyItsOwnFields(): void
    {
        $this->assertSame(['AND' => ['Note.language IS NOT NULL', ['Note.language' => 'en']]], $this->tool()->conditions(['language' => 'en']));
        $this->assertSame(
            ['AND' => ['Opinion.comment IS NOT NULL', ['Opinion.comment LIKE' => 'agree%']]],
            $this->tool('Opinion')->conditions(['comment' => ['LIKE' => 'agree%']])
        );
        $this->assertSame(['Relationship.related_object_type' => 'Event'], $this->tool('Relationship')->conditions(['related_object_type' => 'Event']));
        $unknown = [
            'Note' => ['opinion', 'comment', 'relationship_type', 'related_object_uuid'],
            'Opinion' => ['note', 'language', 'related_object_type'],
            'Relationship' => ['note', 'opinion'],
        ];
        foreach ($unknown as $type => $fields) {
            foreach (array_merge($fields, ['content', 'node_count', 'sharing_group_id', 'name', 'tags', 'Note.id']) as $field) {
                $error = $this->errors([$field => 1], $type)[0];
                $this->assertSame(['unknown_field', 'query.<unknown>'], [$error['code'], $error['path']], "$type $field");
            }
        }
    }

    public function testOrderIsTheTypesOwnWhitelist(): void
    {
        $this->tool('Opinion')->validateOrder(['opinion desc', 'Opinion.modified'], Opinion::REST_SEARCH_ORDER_FIELDS, 'Opinion');
        $this->tool('Relationship')->validateOrder('relationship_type', Relationship::REST_SEARCH_ORDER_FIELDS, 'Relationship');
        foreach (['opinion', 'note', 'uuid', 'Opinion.id', 'id sideways'] as $order) {
            try {
                $this->tool()->validateOrder($order, Note::REST_SEARCH_ORDER_FIELDS, 'Note');
                $this->fail("accepted $order");
            } catch (ComplexQueryException $e) {
                $this->assertSame('order[0]', $e->errors[0]['path'], $order);
            }
        }
    }

    public function testDiscoveryListsEveryField(): void
    {
        $model = new AnalystDataQueryStubRelationship();
        $d = $this->tool('Relationship')->discovery('relationships', '/analyst_data/restSearch/Relationship', Relationship::REST_SEARCH_ORDER_FIELDS, 'Relationship');
        $table = $d['tables']['relationships'];
        $this->assertSame(array_keys($model->queryFields()), array_keys($table['fields']));
        $this->assertSame(['id', 'created', 'modified', 'distribution', 'relationship_type'], $table['sortable']);
        $this->assertSame('datetime', $table['fields']['modified']['type']);
        $this->assertSame(['relationship'], $table['fields']['related_object_uuid']['level']);
        $this->assertSame(['=', '!=', 'IN', 'NOT IN'], $table['fields']['org']['operators']);
    }
}
