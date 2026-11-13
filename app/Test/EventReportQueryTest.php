<?php
/**
 * The `query` fields of /event_reports/restSearch (EventReport::QUERY_FIELDS)
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
if (!defined('APP')) {
    define('APP', dirname(__DIR__) . '/');
}

require_once __DIR__ . '/../Model/EventReport.php';

use PHPUnit\Framework\TestCase;

class EventReportQueryStubHandlers
{
    public $alias;

    public function __construct($alias)
    {
        $this->alias = $alias;
    }

    public function set_filter_org(&$params, $conditions, $options)
    {
        return ['Event.orgc_id' => $params['org']['OR']];
    }

    public function set_filter_eventinfo(&$params, $conditions, $options)
    {
        return ['Event.info LIKE' => $params['eventinfo']['OR'][0]];
    }

    public function fetchTagIdsSimple($tags)
    {
        return $tags === ['missing'] ? [-1] : [7, 8];
    }
}

/**
 * The real EventReport::set_filter_tags() over stubbed associations.
 */
class EventReportQueryStubModel extends EventReport
{
    public function __construct()
    {
        $this->alias = 'EventReport';
        $this->Event = new EventReportQueryStubHandlers('Event');
        $this->Event->EventTag = new EventReportQueryStubHandlers('EventTag');
        $this->EventReportTag = new EventReportQueryStubHandlers('EventReportTag');
        $this->EventReportTag->Tag = new EventReportQueryStubHandlers('Tag');
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

class EventReportQueryTest extends TestCase
{
    private function tool(): ComplexQueryTool
    {
        return new ComplexQueryTool(new EventReportQueryStubModel(), [], EventReport::QUERY_FIELDS);
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

    public function testReportAndEventColumnsAreNative(): void
    {
        $tool = $this->tool();
        $this->assertSame(['EventReport.name LIKE' => 'apt%'], $tool->conditions(['name' => ['LIKE' => 'apt%']]));
        $this->assertSame(['EventReport.deleted' => 1], $tool->conditions(['deleted' => true]));
        $this->assertSame(['EventReport.timestamp >=' => 1699444800], $tool->conditions(['timestamp' => ['>=' => '7d']]));
        $this->assertSame(['Event.org_id' => [1, 2]], $tool->conditions(['org_id' => ['IN' => [1, 2]]]));
        $this->assertSame(['Event.published' => 0], $tool->conditions(['published' => false]));
    }

    public function testDatesAreTheEventDate(): void
    {
        $tool = $this->tool();
        $this->assertSame(['Event.date >=' => '2023-11-08'], $tool->conditions(['date' => ['>=' => '7d']]));
        $this->assertSame(['Event.date' => '2024-02-29'], $tool->conditions(['date' => '2024-02-29']));
        foreach (['2023-02-30', '7h', 20231115] as $bad) {
            $this->assertSame(['bad_type'], array_column($this->errors(['date' => $bad]), 'code'), json_encode($bad));
        }
    }

    public function testNegatedContentAlsoMatchesAnEmptyReport(): void
    {
        $this->assertSame(
            ['NOT' => ['AND' => ['EventReport.content IS NOT NULL', ['EventReport.content LIKE' => '%apt%']]]],
            $this->tool()->conditions(['content' => ['NOT LIKE' => '%apt%']])
        );
    }

    public function testEventFieldsUseTheLegacyHandlers(): void
    {
        $tool = $this->tool();
        $this->assertSame(['Event.orgc_id' => ['CIRCL']], $tool->conditions(['org' => 'CIRCL']));
        $this->assertSame(['Event.info LIKE' => '%ransom%'], $tool->conditions(['eventinfo' => ['LIKE' => '%ransom%']]));
        $this->assertSame(['unknown_operator'], array_column($this->errors(['org' => ['LIKE' => '%CIRCL%']]), 'code'));
    }

    public function testTagsAreOnTheReportOrItsEvent(): void
    {
        $tagged = ['OR' => [
            ['EventReport.id IN (EventReportTag.event_report_id)' => ['EventReportTag.tag_id' => [7, 8]]],
            ['EventReport.event_id IN (EventTag.event_id)' => ['EventTag.tag_id' => [7, 8]]],
        ]];
        $this->assertSame($tagged, $this->tool()->conditions(['tags' => ['LIKE' => 'tlp:%']]));
        $this->assertSame(['NOT' => $tagged], $this->tool()->conditions(['tags' => ['!=' => 'tlp:red']]));
        $this->assertSame(
            ['EventReport.id IN (EventReportTag.event_report_id)' => ['EventReportTag.tag_id' => [-1]]],
            $this->tool()->conditions(['tags' => 'missing'])['OR'][0]
        );
    }

    public function testFieldsOutsideTheMapAreUnknown(): void
    {
        foreach (['sharing_group_id', 'user_id', 'Event.info', 'info'] as $field) {
            $error = $this->errors([$field => 1])[0];
            $this->assertSame(['unknown_field', 'query.<unknown>'], [$error['code'], $error['path']], $field);
        }
        $this->assertSame(['unknown_operator'], array_column($this->errors(['uuid' => ['LIKE' => '%a%']]), 'code'));
    }

    public function testMentionsFindsTheDeletedFieldAnywhere(): void
    {
        $tool = $this->tool();
        $this->assertTrue(ComplexQueryTool::mentions($tool->validate(['deleted' => true]), 'deleted'));
        $this->assertTrue(ComplexQueryTool::mentions(
            $tool->validate(['AND' => [['id' => 1], ['NOT' => ['OR' => [['name' => 'x'], ['deleted' => false]]]]]]),
            'deleted'
        ));
        $this->assertFalse(ComplexQueryTool::mentions($tool->validate(['AND' => [['id' => 1], ['NOT' => ['name' => 'x']]]]), 'deleted'));
    }

    public function testOrderIsTheReportsOwnColumns(): void
    {
        $tool = $this->tool();
        $tool->validateOrder(['name desc', 'EventReport.timestamp'], EventReport::REST_SEARCH_ORDER_FIELDS, 'EventReport');
        foreach (['content', 'Event.info', 'uuid', 'id sideways'] as $order) {
            try {
                $tool->validateOrder($order, EventReport::REST_SEARCH_ORDER_FIELDS, 'EventReport');
                $this->fail("accepted $order");
            } catch (ComplexQueryException $e) {
                $this->assertSame('order[0]', $e->errors[0]['path'], $order);
            }
        }
    }

    public function testDiscoveryListsEveryField(): void
    {
        $d = $this->tool()->discovery('event_reports', '/event_reports/restSearch', EventReport::REST_SEARCH_ORDER_FIELDS, 'EventReport');
        $table = $d['tables']['event_reports'];
        $this->assertSame(array_keys(EventReport::QUERY_FIELDS), array_keys($table['fields']));
        $this->assertSame(['id', 'event_id', 'name', 'timestamp', 'distribution'], $table['sortable']);
        $this->assertSame('date', $table['fields']['date']['type']);
        $this->assertSame(['event_report', 'event'], $table['fields']['tags']['level']);
    }
}
