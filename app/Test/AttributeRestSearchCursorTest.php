<?php
use PHPUnit\Framework\TestCase;

class App { public static function uses($class, $package) {} }
#[AllowDynamicProperties]
class AppModel {}
class Component {}
class Inflector { public static function tableize($name) { return strtolower($name) . "s"; } }
#[AllowDynamicProperties]
class Controller {}
class Configure {
    public static function read($key) { return false; }
    public static function check($key) { return false; }
}
class BadRequestException extends Exception {}
class ClassRegistry {
    public static $allowedIds = [];
    public static function init($name) {
        if ($name === 'Allowedlist') { return new CursorAllowedlist(); }
        throw new Exception($name);
    }
}
class CursorAllowedlist {
    public function removeAllowedlistedFromArray($rows, $unused) {
        return array_filter($rows, function ($row) {
            return !in_array($row['Attribute']['id'], ClassRegistry::$allowedIds);
        });
    }
}
class CursorEvent {
    public $ThreatLevel;
    public $Org;
    public function __construct() {
        $this->ThreatLevel = new CursorDependency();
        $this->Org = new CursorDependency();
    }
    public function harvestSubqueryElements($filters) { return []; }
    public function addFiltersFromSubqueryElements($filters, $elements, $user) { return $filters; }
    public function addFiltersFromUserSettings($user, $filters) { return $filters; }
}
class CursorDependency {
    public function authorizedIds($user) { return []; }
    public function hasNamedIndex($table, $index) { return false; }
    public function find($type, $params) {
        return $type === 'first' ? ['Org' => ['id' => 1]] : [];
    }
    public function filterWarninglistAttribute($attribute) {
        return $attribute['id'] > 4;
    }
}
require_once __DIR__ . '/../Lib/Tools/TmpFileTool.php';
require_once __DIR__ . '/../Model/MispAttribute.php';
require_once __DIR__ . '/../Controller/Component/RestSearchComponent.php';
require_once __DIR__ . '/../Controller/AppController.php';
require_once __DIR__ . '/../Lib/Tools/JsonTool.php';
foreach (['Json', 'Text', 'Cache', 'Hashes', 'Count'] as $name) {
    require_once __DIR__ . '/../Lib/Export/' . $name . 'Export.php';
}
class CursorRequest {
    public $params = ['named' => []];
    public $data;
    public function is($type) { return $type === 'post'; }
}
class CursorAuth {
    public function user() { return ['Role' => ['perm_sync' => false]]; }
}
class CursorUser {
    public $roleLimit = 0;
    public function getUserRestLimit($user, $controller) { return $this->roleLimit; }
}
class CursorResponse {
    public function viewData($file, $type, $false, $true, $name, $headers) {
        return ['body' => $file->intoString(), 'headers' => $headers];
    }
}
class CursorController extends AppController {
    public $filters;
    public $modelClass = 'MispAttribute';
    public function __construct($filters) {
        $this->filters = $filters;
        $this->MispAttribute = new CursorSqlAttribute(range(1, 6));
        $this->request = new CursorRequest();
        $this->request->data = $filters;
        $this->RestSearch = new RestSearchComponent();
        $this->Auth = new CursorAuth();
        $this->User = new CursorUser();
        $this->RestResponse = new CursorResponse();
    }
    protected function _closeSession($saveSession = false) { return $this->Auth->user(); }
}


class CursorSqlAttribute extends MispAttribute {
    public $queries = [];
    public $ids = [];
    public $filterConditions = [];
    public function __construct($ids) {
        $this->ids = $ids;
        $this->SharingGroup = new CursorDependency();
        $this->Warninglist = new CursorDependency();
        $this->Event = new CursorEvent();
    }
    public function buildFilterConditions(array $user, array &$params, $skipBuildConditions = false) { return $this->filterConditions; }
    protected function convert_to_memory_limit_to_mb($value) { return 1; }
    public function buildConditions($user) { return ['Event.org_id' => 1]; }
    public function getSchemaInspector() { return new CursorDependency(); }
    public function findOrder($order, $model, $fields) { return $order; }
    public function find($type, $params) {
        $this->queries[] = $params;
        if (count($this->queries) > 15) { throw new Exception('Loop stalled'); }
        $after = 0;
        array_walk_recursive($params['conditions'], function ($value, $key) use (&$after) {
            if ($key === 'Attribute.id >') { $after = max($after, $value); }
        });
        $ids = array_values(array_filter($this->ids, function ($id) use ($after) {
            return $id > $after;
        }));
        $ids = array_slice($ids, $params['offset'] ?? 0, $params['limit']);
        return array_map(function ($id) {
            return [
                'Attribute' => ['id' => $id, 'event_id' => 1, 'value' => 'v' . $id, 'type' => 'md5'],
                'Event' => ['org_id' => 1, 'orgc_id' => 1, 'threat_level_id' => 1],
            ];
        }, $ids);
    }
}
class CursorExport {
    public function separator($params) { return ','; }
    public function handler($row, $params) { return (string) $row['Attribute']['id']; }
}

class AttributeRestSearchCursorTest extends TestCase {
    protected function setUp(): void { ClassRegistry::$allowedIds = []; }

    private function iterate($ids, $params, $loop, $max, &$metadata = null) {
        $model = new CursorSqlAttribute($ids);
        $params += ['page' => 1, 'includeSightingdb' => false, 'conditions' => []];
        $file = new TmpFileTool();
        $skipped = 0;
        $method = new ReflectionMethod(MispAttribute::class, '__iteratedFetch');
        $method->setAccessible(true);
        $count = $method->invokeArgs($model, [
            ['Role' => ['perm_sync' => false]], $params, $loop, $file,
            new CursorExport(), [], $max, &$skipped, &$metadata,
        ]);
        return [$file->intoString(), $count, $skipped, $model->queries];
    }

    public function testParamsOnlyFetchStartsAfterCursor() {
        $model = new CursorSqlAttribute(range(1, 6));
        $user = ['Role' => ['perm_sync' => false]];
        $params = $model->restSearch($user, 'json', [
            'after_id' => 3, 'limit' => 2,
        ], true);
        $rows = $model->fetchAttributes($user, $params);
        $this->assertSame([4, 5], array_column(array_column($rows, 'Attribute'), 'id'));
        $this->assertSame('Attribute.id ASC', $model->queries[0]['order']);
        $this->assertContains(['Event.org_id' => 1], $model->queries[0]['conditions']['AND']);
    }

    public function testParamsOnlyCursorPreservesStricterExistingBound() {
        $model = new CursorSqlAttribute(range(1, 6));
        $model->filterConditions = ['Attribute.id >' => 4];
        $user = ['Role' => ['perm_sync' => false]];
        $params = $model->restSearch($user, 'json', [
            'after_id' => 3, 'limit' => 2,
        ], true);
        $rows = $model->fetchAttributes($user, $params);
        $this->assertSame([5, 6], array_column(array_column($rows, 'Attribute'), 'id'));
    }

    public function testContinuesAcrossCompletelyFilteredBatches() {
        [$body, $count, $skipped] = $this->iterate(range(1, 6),
            ['limit' => 2, 'enforceWarninglist' => true], true, 2);
        $this->assertSame('5,6', $body);
        $this->assertSame(6, $count);
        $this->assertSame(4, $skipped);
    }

    public function testAllowedlistedTailStillAdvancesRawCursor() {
        ClassRegistry::$allowedIds = [2, 3, 4];
        [$body, $count, , $queries] = $this->iterate(range(1, 6), ['limit' => 2], true, 2);
        $this->assertSame('1,5,6', $body);
        $this->assertSame(6, $count);
        $this->assertCount(4, $queries);
    }

    public function testExactMultipleLimitNeverRunsZeroLimitQuery() {
        [$body, $count, , $queries] = $this->iterate(range(1, 8), ['limit' => 4], false, 2);
        $this->assertSame('1,2,3,4', $body);
        $this->assertSame(5, $count); // Legacy continuation sentinel.
        $this->assertCount(2, $queries);
    }

    public function testSplitPageKeepsOriginalOffset() {
        [$body, $count] = $this->iterate(range(1, 12), ['limit' => 5, 'page' => 2], false, 2);
        $this->assertSame('6,7,8,9,10', $body);
        $this->assertSame(6, $count); // One sentinel for the whole page.
    }

    public function testPublicCursorMetadataUsesRawTail() {
        ClassRegistry::$allowedIds = [4];
        $metadata = [];
        [$body, $count] = $this->iterate(range(1, 6),
            ['limit' => 3, 'after_id' => 1], false, 2, $metadata);
        $this->assertSame('2,3', $body);
        $this->assertSame(['next_cursor' => 4, 'has_more' => true], $metadata);
        $headers = (new RestSearchComponent())->getCursorHeaders($metadata);
        $this->assertSame(['X-Next-Cursor' => '4', 'X-Has-More' => 'true'], $headers);
    }

    public function testExhaustedCursorKeepsStartAndFalseHasMore() {
        $metadata = [];
        [$body] = $this->iterate([1, 2], ['limit' => 3, 'after_id' => 9], false, 2, $metadata);
        $this->assertSame('', $body);
        $this->assertSame(['next_cursor' => 9, 'has_more' => false], $metadata);
    }

    public function testControllerKeepsJsonShapeAndReturnsCursorHeaders() {
        $controller = new CursorController([
            'after_id' => 1, 'limit' => 3, 'returnFormat' => 'json',
        ]);
        $result = $controller->restSearch();
        $rows = json_decode($result['body'], true)['response']['Attribute'];
        $this->assertSame([2, 3, 4], array_column($rows, 'id'));
        $this->assertSame('v2', $rows[0]['value']);
        $this->assertSame(['id' => 1], $rows[0]['Event']['Org']);
        $this->assertSame('4', $result['headers']['X-Next-Cursor']);
        $this->assertSame('true', $result['headers']['X-Has-More']);
    }

    public function testControllerRejectsExplicitNullCursor() {
        $controller = new CursorController([
            'after_id' => null, 'limit' => 2, 'returnFormat' => 'json',
        ]);
        $this->expectException(BadRequestException::class);
        $controller->restSearch();
    }

    public function testLeanCursorExportBodiesKeepTheirFormats() {
        $expected = [
            'text' => "v2\nv3\n",
            'hashes' => "v2\nv3\n",
            'cache' => md5('v2') . "\n" . md5('v3') . "\n",
        ];
        foreach ($expected as $format => $body) {
            $result = (new CursorController([
                'after_id' => 1, 'limit' => 2, 'returnFormat' => $format,
            ]))->restSearch();
            $this->assertSame($body, $result['body']);
            $this->assertSame('3', $result['headers']['X-Next-Cursor']);
        }
    }

    public function testCacheCursorRejectsPageBeforeOverflowQuery() {
        $controller = new CursorController([
            'after_id' => 0, 'page' => 2, 'limit' => 3, 'returnFormat' => 'cache',
        ]);
        $this->expectException(BadRequestException::class);
        $controller->restSearch();
    }

    public function testRoleLimitBoundsCursorProgress() {
        $controller = new CursorController([
            'after_id' => 1, 'limit' => 3, 'returnFormat' => 'count',
        ]);
        $controller->User->roleLimit = 2;
        $result = $controller->restSearch();
        $this->assertSame('2', $result['body']);
        $this->assertSame('3', $result['headers']['X-Next-Cursor']);
    }

    public function testControllerRejectsMissingLimitBeforeApplyingRoleLimit() {
        $controller = new CursorController(['after_id' => 0, 'returnFormat' => 'json']);
        $controller->User->roleLimit = 2;
        $this->expectException(BadRequestException::class);
        $controller->restSearch();
    }

    public function testNonCursorControllerOmitsContinuationHeaders() {
        $controller = new CursorController(['limit' => 2, 'page' => 2, 'returnFormat' => 'json']);
        $result = $controller->restSearch();
        $rows = json_decode($result['body'], true)['response']['Attribute'];
        $this->assertSame([3, 4], array_column($rows, 'id'));
        $this->assertArrayNotHasKey('X-Next-Cursor', $result['headers']);
    }

    public function testLegacyFullPageRetainsCountContinuationSentinel() {
        $full = (new CursorController([
            'limit' => 2, 'returnFormat' => 'json',
        ]))->restSearch();
        $partial = (new CursorController([
            'limit' => 10, 'returnFormat' => 'json',
        ]))->restSearch();
        $cursor = (new CursorController([
            'after_id' => 0, 'limit' => 2, 'returnFormat' => 'json',
        ]))->restSearch();
        $this->assertSame(3, $full['headers']['X-Result-Count']);
        $this->assertSame(6, $partial['headers']['X-Result-Count']);
        $this->assertSame(2, $cursor['headers']['X-Result-Count']);
    }

    public function testPartialCursorPageHasNoMoreRows() {
        $metadata = [];
        [$body] = $this->iterate([1, 2, 3], ['limit' => 4, 'after_id' => 1], false, 3, $metadata);
        $this->assertSame('2,3', $body);
        $this->assertSame(['next_cursor' => 3, 'has_more' => false], $metadata);
    }

    public function testCursorWithAllRowsFilteredStillReturnsProgress() {
        $metadata = [];
        [$body] = $this->iterate(range(1, 6), [
            'limit' => 3, 'after_id' => 0, 'enforceWarninglist' => true,
        ], false, 2, $metadata);
        $this->assertSame('', $body);
        $this->assertSame(['next_cursor' => 3, 'has_more' => true], $metadata);
    }

    public function testCountCursorCountsOnlyPostfilteredRows() {
        $controller = new CursorController([
            'after_id' => 0, 'limit' => 6, 'returnFormat' => 'count',
            'enforceWarninglist' => true,
        ]);
        ClassRegistry::$allowedIds = [6];
        $result = $controller->restSearch();
        $this->assertSame('1', $result['body']);
        $this->assertSame('6', $result['headers']['X-Next-Cursor']);
    }

    /** @dataProvider invalidCursorFilters */
    public function testRejectsInvalidCursorRequests($filters) {
        $this->expectException(BadRequestException::class);
        (new CursorSqlAttribute([]))->validateRestSearchCursor($filters, 'json');
    }

    public function invalidCursorFilters() {
        return array_map(function ($filters) { return [$filters]; }, [
            ['after_id' => -1, 'limit' => 2],
            ['after_id' => '1.5', 'limit' => 2],
            ['after_id' => true, 'limit' => 2],
            ['after_id' => null, 'limit' => 2],
            ['after_id' => '9999999999999999999999999', 'limit' => 2],
            ['after_id' => 0],
            ['after_id' => 0, 'limit' => 0],
            ['after_id' => 0, 'limit' => 2, 'page' => 1],
            ['after_id' => 0, 'limit' => 2, 'order' => 'Attribute.id DESC'],
            ['after_id' => 0, 'limit' => 2, 'order' => 'value'],
            ['after_id' => 0, 'limit' => 2, 'list' => true],
        ]);
    }

    public function testAcceptsAscendingIdAndLeanFormats() {
        foreach (['json', 'text', 'cache', 'hashes', 'count'] as $format) {
            $this->assertSame(0, (new CursorSqlAttribute([]))->validateRestSearchCursor(
                ['after_id' => '0', 'limit' => '2', 'order' => 'Attribute.id ASC'], $format));
        }
    }
}
