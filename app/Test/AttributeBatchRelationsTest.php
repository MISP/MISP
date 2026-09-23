<?php
/** Standalone regression tests; run separately from CakePHP bootstrap tests. */
use PHPUnit\Framework\TestCase;

if (!class_exists('App', false)) {
    class App { public static function uses($class, $package) {} }
}
if (!class_exists('Model', false)) {
    #[AllowDynamicProperties]
    class Model {}
}
if (!class_exists('AppModel', false)) {
    class AppModel extends Model {}
}
if (!class_exists('ModelBehavior', false)) {
    class ModelBehavior {}
}
if (!class_exists('Configure', false)) {
    class Configure { public static function read($key) { return null; } }
}
require_once __DIR__ . '/../Model/Correlation.php';
require_once __DIR__ . '/../Model/MispAttribute.php';
if (file_exists(__DIR__ . '/../Model/Behavior/RelatedAttributeBatchTrait.php')) {
    require_once __DIR__ . '/../Model/Behavior/RelatedAttributeBatchTrait.php';
}
require_once __DIR__ . '/../Model/Behavior/DefaultCorrelationBehavior.php';
require_once __DIR__ . '/../Model/Behavior/NoAclCorrelationBehavior.php';
require_once __DIR__ . '/../Model/Behavior/OnDemandCorrelationBehavior.php';

/** Replaces only database I/O, including the selected fields and conditions. */
class BatchRelationRows extends Model
{
    public $rows = [];
    public $queries = [];
    public $visibleIds = [];
    public function fetchAttributesSimple($user, $query)
    {
        $query['conditions']['Attribute.id'] = array_values(array_intersect(
            $query['conditions']['Attribute.id'], $this->visibleIds
        ));
        return $this->find('all', $query);
    }
    public function find($type, $query)
    {
        $this->queries[] = $query;
        $rows = array_values(array_filter($this->rows, function ($row) use ($query) {
            foreach ($query['conditions'] as $field => $expected) {
                $different = substr($field, -3) === ' !=';
                $field = str_replace(' !=', '', $field);
                list($alias, $name) = explode('.', $field);
                $actual = $row[$alias][$name];
                $matches = is_array($expected)
                    ? in_array($actual, $expected) : $actual == $expected;
                if ($different ? $matches : !$matches) {
                    return false;
                }
            }
            return true;
        }));
        foreach ($rows as &$row) {
            if (!empty($query['fields'])) {
                $alias = isset($row['Correlation']) ? 'Correlation' : 'Attribute';
                $fields = array_map(function ($field) use ($alias) {
                    return str_replace($alias . '.', '', $field);
                }, $query['fields']);
                $row[$alias] = array_intersect_key($row[$alias], array_flip($fields));
            }
            if (empty($query['contain']['Event'])) {
                unset($row['Event']);
            }
        }
        if ($type === 'column') {
            $field = $query['fields'][0];
            return array_column(array_column($rows, 'Correlation'), $field);
        }
        return $rows;
    }
}

class BatchTestCorrelation extends Correlation
{
    public $backend;
    public $storage;
    public $engineName = 'Default';
    public function __construct() {}
    public function getCorrelationModelName() { return $this->engineName; }
    public function find($type, $query) { return $this->storage->find($type, $query); }
    public function __call($method, $args)
    {
        return $this->backend->$method($this, ...$args);
    }
}

class AttributeBatchRelationsTest extends TestCase
{
    private function fixture()
    {
        $model = new BatchTestCorrelation();
        $model->backend = new DefaultCorrelationBehavior();
        $model->storage = new BatchRelationRows();
        $model->Attribute = new BatchRelationRows();
        // Deliberately use hydration order different from correlation order.
        foreach ([13, 11, 12, 14, 15, 16, 17] as $id) {
            $model->Attribute->rows[] = [
                'Attribute' => ['id' => $id, 'value' => 'value-' . $id, 'deleted' => 0],
                'Event' => ['id' => 200 + $id, 'info' => 'related event'],
            ];
        }
        foreach ([11, 12, 13, 14, 15, 16, 17] as $id) {
            $corr = [
                'attribute_id' => 1, 'event_id' => 100,
                '1_attribute_id' => $id, '1_event_id' => 200 + $id,
                '1_org_id' => 2, '1_event_distribution' => 3,
                '1_event_sharing_group_id' => 0, '1_object_id' => 0,
                '1_object_distribution' => 5, '1_object_sharing_group_id' => 0,
                '1_distribution' => 5, '1_sharing_group_id' => 0,
            ];
            if ($id === 12) { $corr['1_event_distribution'] = 0; }
            if ($id === 13) {
                $corr['1_distribution'] = 4;
                $corr['1_sharing_group_id'] = 7;
            }
            if ($id === 14) {
                $corr['1_object_id'] = 5;
                $corr['1_object_distribution'] = 0;
            }
            if ($id === 15) { $corr['1_event_id'] = 100; }
            if ($id === 16) {
                $corr['1_event_distribution'] = 4;
                $corr['1_event_sharing_group_id'] = 8;
            }
            if ($id === 17) {
                $corr['1_object_id'] = 6;
                $corr['1_object_distribution'] = 4;
                $corr['1_object_sharing_group_id'] = 8;
            }
            $model->storage->rows[] = ['Correlation' => $corr];
            // Reverse direction for source 2 in a different event.
            $reverse = [];
            foreach ($corr as $field => $value) {
                $reverse[substr($field, 0, 2) === '1_'
                    ? substr($field, 2) : '1_' . $field] = $value;
            }
            $reverse['1_attribute_id'] = 2;
            $reverse['1_event_id'] = 300;
            $model->storage->rows[] = ['Correlation' => $reverse];
        }
        // Duplicate edge must not duplicate the hydrated attribute.
        $model->storage->rows[] = $model->storage->rows[0];
        return $model;
    }

    public function testBatchPreservesLegacyAclOrderingAndEventShape()
    {
        $this->assertTrue(method_exists(Correlation::class, 'getRelatedAttributesBatch'));
        $sources = [
            ['id' => 1, 'event_id' => 100, 'type' => 'domain'],
            ['id' => 2, 'event_id' => 300, 'type' => 'domain'],
            ['id' => 3, 'event_id' => 100, 'type' => 'comment'],
        ];
        foreach ([[false, 1, []], [false, 1, [7, 8]], [false, 2, []], [true, 1, []]] as $acl) {
            $user = ['Role' => ['perm_site_admin' => $acl[0]], 'org_id' => $acl[1]];
            foreach ([false, true] as $eventData) {
                foreach ([['id', 'value'], ['value'], []] as $fields) {
                    $model = $this->fixture();
                    $expected = [];
                    foreach ($sources as $source) {
                        $expected[$source['id']] = $model->getRelatedAttributes(
                            $user, $acl[2], $source, $fields, $eventData
                        );
                    }
                    $model->storage->queries = [];
                    $model->Attribute->queries = [];
                    $actual = $model->getRelatedAttributesBatch(
                        $user, $acl[2], $sources, $fields, $eventData
                    );
                    $this->assertSame($expected, $actual);
                    $this->assertCount(2, $model->storage->queries);
                    $this->assertCount(1, $model->Attribute->queries);
                }
            }
        }
        $model = $this->fixture();
        $actual = $model->getRelatedAttributesBatch(
            ['Role' => ['perm_site_admin' => false], 'org_id' => 1],
            [7], $sources, ['id'], true
        );
        $this->assertSame([13, 11], array_column($actual[1], 'id'));
        $this->assertSame([13, 11, 15], array_column($actual[2], 'id'));
        $this->assertSame([], $actual[3]);
    }

    public function testCorrelationQueriesGrowByChunksAndPreserveAllMatches()
    {
        $this->assertTrue(method_exists(Correlation::class, 'getRelatedAttributesBatch'));
        $model = $this->fixture();
        $sources = [];
        for ($id = 1; $id <= 205; ++$id) {
            $sources[] = ['id' => $id, 'event_id' => 900, 'type' => 'domain'];
        }
        $actual = $model->getRelatedAttributesBatch(
            ['Role' => ['perm_site_admin' => true]], [], $sources, ['id'], true
        );
        $this->assertCount(205, $actual);
        $this->assertSame([13, 11, 12, 14, 15, 16, 17], array_column($actual[1], 'id'));
        $this->assertCount(6, $model->storage->queries);
        foreach ($model->storage->queries as $query) {
            $this->assertLessThanOrEqual(100, count(reset($query['conditions'])));
        }
    }

    public function testNoAclBatchPreservesUnrestrictedResults()
    {
        $this->assertTrue(method_exists(Correlation::class, 'getRelatedAttributesBatch'));
        $model = $this->fixture();
        $model->backend = new NoAclCorrelationBehavior();
        $model->engineName = 'NoAcl';
        $sources = [
            ['id' => 1, 'event_id' => 100, 'type' => 'domain'],
            ['id' => 2, 'event_id' => 300, 'type' => 'domain'],
        ];
        $user = ['Role' => ['perm_site_admin' => false], 'org_id' => 1];
        $expected = [];
        foreach ($sources as $source) {
            $expected[$source['id']] = $model->getRelatedAttributes(
                $user, [], $source, ['id'], true
            );
        }
        $model->storage->queries = [];
        $model->Attribute->queries = [];
        $actual = $model->getRelatedAttributesBatch($user, [], $sources, ['id'], true);
        $this->assertSame($expected, $actual);
        $this->assertSame([13, 11, 12, 14, 16, 17], array_column($actual[1], 'id'));
        $this->assertCount(2, $model->storage->queries);
        $this->assertCount(1, $model->Attribute->queries);
    }

    public function testOnDemandFallbackUsesLiveAclInsteadOfStoredPermissions()
    {
        $model = $this->fixture();
        $model->engineName = 'OnDemand';
        $model->backend = new OnDemandCorrelationBehavior();
        $model->backend->Correlation = $model;
        // Live rows allow a formerly private event, but deny stored-public ones.
        $model->Attribute->visibleIds = [12];
        $sources = [
            ['id' => 1, 'event_id' => 100, 'type' => 'domain'],
            ['id' => 2, 'event_id' => 300, 'type' => 'domain'],
            ['id' => 3, 'event_id' => 300, 'type' => 'comment'],
        ];
        $user = ['Role' => ['perm_site_admin' => false], 'org_id' => 1];
        $result = $model->getRelatedAttributesBatch($user, [], $sources, ['id'], true);
        $this->assertSame([12], array_column($result[1], 'id'));
        $this->assertSame([12], array_column($result[2], 'id'));
        $this->assertSame([], $result[3]);
        $this->assertCount(4, $model->storage->queries);
    }

    public function testLargeFanoutIsNotTruncatedAndNoAclQueriesAreBounded()
    {
        $model = $this->fixture();
        $model->engineName = 'NoAcl';
        $model->backend = new NoAclCorrelationBehavior();
        $template = $model->storage->rows[0]['Correlation'];
        $model->storage->rows = [];
        $model->Attribute->rows = [];
        $sources = [];
        for ($id = 1; $id <= 205; ++$id) {
            $sources[] = ['id' => $id, 'event_id' => 100, 'type' => 'domain'];
            $corr = $template;
            $corr['1_attribute_id'] = 1000 + $id;
            $model->storage->rows[] = ['Correlation' => $corr];
            $model->Attribute->rows[] = ['Attribute' => ['id' => 1000 + $id]];
        }
        $result = $model->getRelatedAttributesBatch(
            ['Role' => ['perm_site_admin' => false], 'org_id' => 1],
            [], $sources, ['id'], false
        );
        $this->assertCount(205, $result[1]);
        $this->assertSame(['Attribute' => ['id' => 1205]], $result[1][204]);
        $this->assertSame([], $result[205]);
        $this->assertCount(6, $model->storage->queries);
        $this->assertCount(1, $model->Attribute->queries);
    }

    public function testEmptyAndNonCorrelatingSourcesDoNotQuery()
    {
        $model = $this->fixture();
        $this->assertSame([], $model->getRelatedAttributesBatch([], [], []));
        $this->assertSame([1 => []], $model->getRelatedAttributesBatch([], [], [
            ['id' => 1, 'event_id' => 100, 'type' => 'comment'],
        ]));
        $this->assertSame([], $model->storage->queries);
        $this->assertSame([], $model->Attribute->queries);
    }

    public function testEventTagsAreBatchedInheritedAndNegativeCached()
    {
        $this->assertTrue(method_exists(MispAttribute::class, '__fetchEventTagsForAttributes'));
        $attribute = (new ReflectionClass(MispAttribute::class))->newInstanceWithoutConstructor();
        $tags = new BatchRelationRows();
        $tags->rows = [
            ['EventTag' => ['id' => 4, 'event_id' => 1, 'local' => 1],
             'Tag' => ['id' => 7, 'name' => 'public', 'colour' => '#fff', 'exportable' => 1]],
            ['EventTag' => ['id' => 5, 'event_id' => 1, 'local' => 0],
             'Tag' => ['id' => 8, 'name' => 'private', 'colour' => '#000', 'exportable' => 0]],
        ];
        $attribute->Event = (object)['EventTag' => $tags];
        $fetch = new ReflectionMethod(MispAttribute::class, '__fetchEventTagsForAttributes');
        $fetch->setAccessible(true);
        $attach = new ReflectionMethod(MispAttribute::class, '__attachEventTagsToAttributes');
        $attach->setAccessible(true);
        $batch = [];
        for ($id = 1; $id <= 205; ++$id) {
            $batch[] = ['Event' => ['id' => $id]];
        }
        foreach ([false, true] as $allTags) {
            $cache = [];
            $tags->queries = [];
            $options = ['includeAllTags' => $allTags];
            $legacyCache = [];
            $expected = $attach->invokeArgs($attribute, [&$legacyCache, $batch[0], $options]);
            $tags->queries = [];
            $fetch->invokeArgs($attribute, [&$cache, $batch, $options]);
            $fetch->invokeArgs($attribute, [&$cache, $batch, $options]);
            $result = $attach->invokeArgs($attribute, [&$cache, $batch[0], $options]);
            $this->assertSame($expected, $result);
            $this->assertCount($allTags ? 2 : 1, $result['EventTag']);
            $this->assertTrue($result['EventTag'][0]['Tag']['inherited']);
            $this->assertSame(1, $result['EventTag'][0]['local']);
            $this->assertSame([], $cache[205]);
            $this->assertCount(3, $tags->queries);
        }
    }
}
