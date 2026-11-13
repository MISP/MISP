<?php
/**
 * The `query` fields of /galaxy_clusters/restSearch (GalaxyCluster::QUERY_FIELDS)
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

require_once __DIR__ . '/../Model/GalaxyCluster.php';

use PHPUnit\Framework\TestCase;

class GalaxyClusterQueryStubModel
{
    public $alias = 'GalaxyCluster';
    public $Orgc;
    public $Galaxy;

    public function __construct()
    {
        $this->Orgc = (object)['alias' => 'Orgc'];
        $this->Galaxy = (object)['alias' => 'Galaxy'];
    }

    public function subQueryGenerator($model, array $options, $lookupKey)
    {
        return ["$lookupKey IN ({$options['fields'][0]} AS {$options['alias']})" => $options['conditions']];
    }
}

class GalaxyClusterQueryTest extends TestCase
{
    private function tool(): ComplexQueryTool
    {
        return new ComplexQueryTool(new GalaxyClusterQueryStubModel(), [], GalaxyCluster::QUERY_FIELDS);
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
        $this->assertSame(['GalaxyCluster.value' => 'APT28'], $tool->conditions(['value' => 'APT28']));
        $this->assertSame(['GalaxyCluster.value LIKE' => 'apt%'], $tool->conditions(['value' => ['LIKE' => 'apt%']]));
        $this->assertSame(['GalaxyCluster.default' => 1], $tool->conditions(['default' => true]));
        $this->assertSame(['GalaxyCluster.distribution >=' => 3], $tool->conditions(['distribution' => ['>=' => 3]]));
    }

    public function testNegatingANullableColumnAlsoMatchesNull(): void
    {
        $this->assertSame(
            ['NOT' => ['AND' => ['GalaxyCluster.description IS NOT NULL', ['GalaxyCluster.description LIKE' => '%x%']]]],
            $this->tool()->conditions(['description' => ['NOT LIKE' => '%x%']])
        );
    }

    public function testGalaxyFieldsMatchThroughTheGalaxyId(): void
    {
        $this->assertSame(
            ['GalaxyCluster.galaxy_id IN (Galaxy.id AS Galaxy)' => [['Galaxy.name LIKE' => 'Threat%']]],
            $this->tool()->conditions(['galaxy_name' => ['LIKE' => 'Threat%']])
        );
        $this->assertSame(
            ['NOT' => ['GalaxyCluster.galaxy_id IN (Galaxy.id AS Galaxy)' => [['Galaxy.namespace' => 'misp']]]],
            $this->tool()->conditions(['galaxy_namespace' => ['!=' => 'misp']])
        );
    }

    public function testOrgIsTheCreatorByNameOrUuidInAnyCase(): void
    {
        $this->assertSame(
            ['GalaxyCluster.orgc_id IN (Orgc.id AS Orgc)' => [['OR' => [
                ['LOWER(Orgc.name)' => ['circl', 'acme']],
                ['LOWER(Orgc.uuid)' => ['circl', 'acme']],
            ]]]],
            $this->tool()->conditions(['org' => ['IN' => ['CIRCL', 'acme']]])
        );
    }

    public function testEveryFieldCompilesAgainstItsOwnTable(): void
    {
        $samples = ['int' => 1, 'bool' => true, 'string' => 'x'];
        foreach (GalaxyCluster::QUERY_FIELDS as $name => $def) {
            $table = isset($def['via']) ? $def['via'][0] : 'GalaxyCluster';
            foreach ((array)$def['column'] as $column) {
                $this->assertStringStartsWith("$table.", $column, $name);
            }
            $this->assertNotEmpty($this->tool()->conditions([$name => $samples[$def['kind']]]), $name);
        }
    }

    public function testRejections(): void
    {
        $this->assertSame('unknown_field', $this->errors(['sharing_group_id' => 1])[0]['code']);
        $this->assertSame('unknown_operator', $this->errors(['org' => ['LIKE' => 'ci%']])[0]['code']);
        $this->assertSame('unknown_operator', $this->errors(['uuid' => ['LIKE' => 'a%']])[0]['code']);
        $this->assertSame('bad_type', $this->errors(['galaxy_id' => '1'])[0]['code']);
    }

    public function testOrder(): void
    {
        $tool = $this->tool();
        $tool->validateOrder('value desc,id', GalaxyCluster::REST_SEARCH_ORDER_FIELDS, 'GalaxyCluster');
        foreach (['0.id', 'event_id', 'Galaxy.name', 'value; drop'] as $order) {
            try {
                $tool->validateOrder($order, GalaxyCluster::REST_SEARCH_ORDER_FIELDS, 'GalaxyCluster');
                $this->fail("accepted $order");
            } catch (ComplexQueryException $e) {
                $this->assertSame('order[0]', $e->errors[0]['path']);
            }
        }
    }

    public function testDiscovery(): void
    {
        $d = $this->tool()->discovery('galaxy_clusters', '/galaxy_clusters/restSearch', GalaxyCluster::REST_SEARCH_ORDER_FIELDS, 'GalaxyCluster');
        $table = $d['tables']['galaxy_clusters'];
        $this->assertSame('/galaxy_clusters/restSearch', $table['endpoint']);
        $this->assertSame(GalaxyCluster::REST_SEARCH_ORDER_FIELDS['GalaxyCluster'], $table['sortable']);
        $this->assertSame(['galaxy'], $table['fields']['galaxy_name']['level']);
        $this->assertSame(['=', '!=', 'IN', 'NOT IN'], $table['fields']['org']['operators']);
    }
}
