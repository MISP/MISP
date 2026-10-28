<?php
require_once __DIR__ . '/../Lib/Tools/ComplexQueryTool.php';

use PHPUnit\Framework\TestCase;

class ComplexQueryStubEvent
{
    public $calls = [];
    public $empty = false;

    public function __call($handler, array $args)
    {
        $this->calls[] = [$handler, $args[0]];
        if ($this->empty) {
            return [];
        }
        $field = array_key_first($args[0]);
        return ["stub:$handler:$field" => $args[0][$field]['OR']];
    }
}

class ComplexQueryStubModel
{
    public $Event;
    public $tagParams = [];

    public function __construct()
    {
        $this->Event = new ComplexQueryStubEvent();
    }

    public function set_filter_tags(&$params, $conditions, $options)
    {
        $this->tagParams[] = $params;
        return ['stub:tags' => $params['tags']['OR']];
    }

    public function resolveTimeDelta($delta)
    {
        return 1000000 - (int)$delta;
    }
}

class ComplexQueryToolTest extends TestCase
{
    private $model;

    protected function setUp(): void
    {
        $this->model = new ComplexQueryStubModel();
    }

    private function tool(array $limits = []): ComplexQueryTool
    {
        return new ComplexQueryTool($this->model, $limits);
    }

    private function errors($query, array $limits = []): array
    {
        try {
            $this->tool($limits)->conditions($query);
        } catch (ComplexQueryException $e) {
            return $e->errors;
        }
        $this->fail('the query was accepted');
    }

    private function codes($query, array $limits = []): array
    {
        return array_column($this->errors($query, $limits), 'code');
    }

    public function testNativeLeaves(): void
    {
        $c = $this->tool()->conditions(['AND' => [
            ['id' => ['>' => 5]],
            ['event_id' => ['IN' => [1, 2]]],
            ['to_ids' => true],
            ['distribution' => ['!=' => 3]],
        ]]);
        $this->assertSame(['AND' => [
            ['Attribute.id >' => 5],
            ['Attribute.event_id' => [1, 2]],
            ['Attribute.to_ids' => 1],
            ['NOT' => ['Attribute.distribution' => 3]],
        ]], $c);
    }

    public function testRelativeTimeIsResolvedThroughTheModel(): void
    {
        $c = $this->tool()->conditions(['timestamp' => ['>=' => '7d']]);
        $this->assertSame(['Attribute.timestamp >=' => 1000000 - 7], $c);
        $c = $this->tool()->conditions(['timestamp' => ['>=' => 1234]]);
        $this->assertSame(['Attribute.timestamp >=' => 1234], $c);
    }

    public function testStringLeavesGoThroughTheHandlers(): void
    {
        $c = $this->tool()->conditions(['OR' => [
            ['type' => 'domain'],
            ['value' => ['LIKE' => '%evil%']],
        ]]);
        $this->assertSame(['OR' => [
            ['stub:set_filter_type:type' => ['domain']],
            ['stub:set_filter_value:value' => ['%evil%']],
        ]], $c);
    }

    public function testNegatedNullableColumnsMatchNullRows(): void
    {
        foreach (['object_relation' => 'Attribute.object_relation', 'comment' => 'Attribute.comment'] as $field => $column) {
            $c = $this->tool()->conditions([$field => ['!=' => 'x']]);
            $this->assertSame(
                ['OR' => [['NOT' => ["stub:" . ($field === 'comment' ? 'set_filter_comment' : 'set_filter_simple_attribute') . ":$field" => ['x']]], "$column IS NULL"]],
                $c
            );
        }
        $c = $this->tool()->conditions(['type' => ['NOT IN' => ['a', 'b']]]);
        $this->assertSame(['NOT' => ['stub:set_filter_type:type' => ['a', 'b']]], $c);
    }

    public function testTagsGetTheSelectiveHintOnlyBesideSelectiveLeaves(): void
    {
        $this->tool()->conditions(['tags' => 'tlp:white']);
        $this->tool()->conditions(['AND' => [['tags' => 'tlp:white'], ['id' => ['>' => 1]]]]);
        $this->tool()->conditions(['AND' => [['tags' => 'tlp:white'], ['type' => 'url']]]);
        $this->tool()->conditions(['OR' => [['tags' => 'tlp:white'], ['type' => 'url']]]);
        $hinted = array_map(function ($p) {
            return isset($p['type']);
        }, $this->model->tagParams);
        $this->assertSame([false, false, true, false], $hinted);
    }

    public function testEmptyHandlerFragmentIsAnError(): void
    {
        $this->model->Event->empty = true;
        $this->assertSame(['bad_type'], $this->codes(['type' => 'x']));
    }

    public function testStrictTypes(): void
    {
        $this->assertSame(['bad_type'], $this->codes(['id' => '5']));
        $this->assertSame(['bad_type'], $this->codes(['id' => 5.0]));
        $this->assertSame(['bad_type'], $this->codes(['id' => true]));
        $this->assertSame(['bad_type'], $this->codes(['to_ids' => 1]));
        $this->assertSame(['bad_type'], $this->codes(['to_ids' => 'true']));
        $this->assertSame(['bad_type'], $this->codes(['type' => 5]));
        $this->assertSame(['bad_type'], $this->codes(['type' => '']));
        $this->assertSame(['bad_type'], $this->codes(['type' => null]));
        $this->assertSame(['bad_type'], $this->codes(['timestamp' => '7days']));
        $this->assertSame(['bad_type'], $this->codes(['timestamp' => 'next friday']));
        $this->assertSame(['bad_type'], $this->codes(['timestamp' => '99999999999d']));
        $this->assertSame(['bad_type'], $this->codes(['id' => ['IN' => [1, '2']]]));
    }

    public function testWildcards(): void
    {
        $this->assertSame(['bad_type'], $this->codes(['value' => '%evil']));
        $this->assertSame(['bad_type'], $this->codes(['value' => ['IN' => ['ok', 'a%']]]));
        $this->assertSame(['bad_type'], $this->codes(['value' => ['LIKE' => 'evil']]));
        $this->assertSame(['bad_type'], $this->codes(['value' => ['LIKE' => '%e%vil%']]));
        $this->assertSame(['bad_type'], $this->codes(['value' => ['LIKE' => '%%']]));
        $this->assertSame(['unknown_operator'], $this->codes(['uuid' => ['LIKE' => '%a']]));
        $this->assertSame(['unknown_operator'], $this->codes(['tags' => ['LIKE' => '%a']]));
        $this->assertSame(['unknown_operator'], $this->codes(['to_ids' => ['IN' => [true]]]));
        $this->assertSame(['unknown_operator'], $this->codes(['type' => ['>' => 'a']]));
        $this->assertSame(['unknown_operator'], $this->codes(['id' => ['LIKE' => 1]]));
        $this->assertSame(['unknown_operator'], $this->codes(['id' => ['=~' => 1]]));
    }

    public function testShapes(): void
    {
        foreach ([
            [], 'x', 5, null, [['id' => 1]],
            ['id' => 1, 'type' => 'a'],
            ['AND' => []], ['AND' => ['id' => 1]], ['OR' => 'x'], ['AND' => [[]]],
            ['NOT' => []], ['NOT' => [['id' => 1]]],
            ['id' => []], ['id' => [1, 2]], ['id' => ['>' => 1, '<' => 5]],
            ['id' => ['IN' => []]], ['id' => ['IN' => 5]], ['id' => ['IN' => ['a' => 1]]],
        ] as $query) {
            $this->assertSame(['bad_shape'], $this->codes($query), json_encode($query));
        }
    }

    public function testUnknownFieldsAndKeywords(): void
    {
        foreach ([['nope' => 1], ['and' => [['id' => 1]]], ['deleted' => 1], ['first_seen' => 1]] as $query) {
            $this->assertSame(['unknown_field'], $this->codes($query), json_encode($query));
        }
    }

    public function testLimits(): void
    {
        $deep = ['id' => 1];
        for ($i = 0; $i < 5; $i++) {
            $deep = ['NOT' => $deep];
        }
        $this->assertSame(['limit_exceeded'], $this->codes($deep));
        $this->tool()->conditions(['NOT' => ['NOT' => ['NOT' => ['NOT' => ['id' => 1]]]]]);

        $wide = ['AND' => array_fill(0, 60, ['id' => 1])];
        $this->assertSame(['limit_exceeded'], $this->codes($wide));
        $this->assertSame(['limit_exceeded'], $this->codes(['id' => ['IN' => range(1, 101)]]));
        $this->assertSame(['limit_exceeded'], $this->codes(['type' => str_repeat('a', 1025)]));
        $this->assertSame(['limit_exceeded'], $this->codes(['AND' => [['id' => 1], ['id' => 2]]], ['max_nodes' => 2]));
    }

    public function testMessagesAndPathsNeverEchoInput(): void
    {
        $marker = 'ZZ_SECRET_ZZ';
        $queries = [
            [$marker => 1],
            ['AND' => [['id' => 1], [$marker => ['OR' => 1]]]],
            ['id' => [$marker => 1]],
            ['id' => $marker],
            ['type' => [$marker => 'a']],
            ['AND' => [['value' => ['LIKE' => $marker]], ['timestamp' => $marker]]],
        ];
        foreach ($queries as $query) {
            $errors = $this->errors($query);
            $this->assertStringNotContainsString($marker, json_encode($errors), json_encode($query));
        }
        $this->assertSame(
            'query.AND[1].<unknown>',
            $this->errors(['AND' => [['id' => 1], [$marker => 1]]])[0]['path']
        );
        $this->assertSame('query.OR[0].id', $this->errors(['OR' => [['id' => 'x']]])[0]['path']);
    }

    public function testEveryErrorIsReportedAndCapped(): void
    {
        $query = ['AND' => [['id' => 'a'], ['nope' => 1], ['type' => 5]]];
        $this->assertSame(['bad_type', 'unknown_field', 'bad_type'], $this->codes($query));
        $many = ['AND' => array_fill(0, 40, ['id' => 'a'])];
        $this->assertCount(10, $this->errors($many));
    }

    public function testValidationDoesNoDatabaseWork(): void
    {
        $this->errors(['AND' => [['type' => 'a'], ['id' => 'bad']]]);
        $this->assertSame([], $this->model->Event->calls);
        $this->assertSame([], $this->model->tagParams);
    }

    private function orderErrors($order): array
    {
        $allowed = ['Attribute' => ['id', 'type', 'timestamp'], 'Event' => ['publish_timestamp']];
        try {
            $this->tool()->validateOrder($order, $allowed);
        } catch (ComplexQueryException $e) {
            return $e->errors;
        }
        return [];
    }

    public function testValidOrderRulesPass(): void
    {
        foreach (['id', 'id desc', 'ID DESC', 'Attribute.type asc', 'Event.publish_timestamp desc', 'id,type desc', ['id', 'Event.publish_timestamp desc']] as $order) {
            $this->assertSame([], $this->orderErrors($order), json_encode($order));
        }
    }

    public function testUnknownOrderRulesAreRejected(): void
    {
        $marker = 'ZZ_ORDER';
        foreach ([$marker, 'id,' . $marker, 'Event.id', 'Org.id', 'a.b.c', 'id up', 'id asc extra', '', [], 5, [5], ['a' => 'id'], 'Event'] as $order) {
            $errors = $this->orderErrors($order);
            $this->assertNotSame([], $errors, json_encode($order));
            $this->assertStringNotContainsString($marker, json_encode($errors));
        }
        $this->assertSame('order[1]', $this->orderErrors('id,nope')[0]['path']);
        $this->assertSame('unknown_field', $this->orderErrors('nope')[0]['code']);
    }

    public function testDescribeListsTheWhitelist(): void
    {
        $d = $this->tool()->describe();
        $this->assertSame(array_keys(ComplexQueryTool::FIELDS), array_keys($d['fields']));
        $this->assertSame(['=', '!='], $d['fields']['to_ids']['operators']);
        $this->assertSame(5, $d['limits']['max_depth']);
    }
}
