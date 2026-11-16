<?php
/**
 * The feed and server event previews print remote JSON that nothing has
 * validated, uuids and ids included: each must come out escaped, and one
 * inside an inline handler must reach the script as a string literal.
 */

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/ViewTemplateHarness.php';
if (!class_exists('Hash', false)) {
    require_once __DIR__ . '/../Lib/cakephp/lib/Cake/Utility/Hash.php';
}

class RemoteEventPreviewEscapingTest extends TestCase
{
    const REMOTE = "x'\"<i>y";

    /** @var ViewTemplateHarness */
    private $view;

    protected function setUp(): void
    {
        $this->view = new ViewTemplateHarness();
    }

    private function remoteAttribute($key)
    {
        return [
            $key => self::REMOTE,
            'type' => 'ip-src',
            'category' => 'Network activity',
            'value' => '192.0.2.1',
            'comment' => '',
            'to_ids' => false,
            'deleted' => false,
            'distribution' => 0,
            'object_relation' => null,
            'timestamp' => 0,
            'Tag' => [],
            'objectType' => 'attribute',
        ];
    }

    private function remoteObject($key)
    {
        return [
            $key => self::REMOTE,
            'name' => 'domain-ip',
            'meta-category' => 'network',
            'description' => '',
            'template_version' => 1,
            'template_uuid' => '43b3b146-77eb-4931-b4cc-b66c60f28734',
            'timestamp' => 0,
            'distribution' => 0,
            'Attribute' => [],
            'ObjectReference' => [[
                'id' => self::REMOTE,
                'uuid' => self::REMOTE,
                'relationship_type' => 'related-to',
                'referenced_id' => self::REMOTE,
                'referenced_uuid' => self::REMOTE,
                'Object' => ['uuid' => self::REMOTE, 'name' => 'file'],
            ]],
            'referenced_by' => ['object' => [[
                'id' => self::REMOTE,
                'uuid' => self::REMOTE,
                'relationship_type' => 'related-to',
                'meta-category' => 'file',
                'name' => 'file',
            ]]],
        ];
    }

    private function render($template, array $vars)
    {
        return $this->view->render($template, $vars + [
            'currentUri' => '/servers/previewEvent/1/2',
            'fieldCount' => 10,
            'distributionLevels' => [0 => 'Your organisation only'],
        ]);
    }

    private function assertEscaped($html)
    {
        $this->assertStringContainsString(h(self::REMOTE), $html);
        $this->assertStringNotContainsString('<i>', $html);
    }

    /** The inline handlers of $html, as the script will read them. */
    private function handlers($html)
    {
        preg_match_all('/\son[a-z]+="([^"]*)"/i', $html, $matches);
        return array_map(function ($handler) {
            return html_entity_decode($handler, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        }, $matches[1]);
    }

    public function feedRowProvider()
    {
        return [
            'attribute' => ['Elements/Feeds/View/row_attribute.ctp', 'remoteAttribute'],
            'object' => ['Elements/Feeds/View/row_object.ctp', 'remoteObject'],
            'references' => ['Elements/Feeds/View/row_object_reference.ctp', 'remoteObject'],
            'referenced by' => ['Elements/Feeds/View/row_object_referenced_by.ctp', 'remoteObject'],
        ];
    }

    /**
     * @dataProvider feedRowProvider
     */
    public function testFeedPreviewRowsEscapeRemoteUuids($template, $builder)
    {
        $this->assertEscaped($this->render($template, ['object' => $this->$builder('uuid')]));
    }

    public function serverRowProvider()
    {
        return [
            'attribute' => ['Elements/Servers/View/row_attribute.ctp', 'remoteAttribute'],
            'object' => ['Elements/Servers/View/row_object.ctp', 'remoteObject'],
            'references' => ['Elements/Servers/View/row_object_reference.ctp', 'remoteObject'],
            'referenced by' => ['Elements/Servers/View/row_object_referenced_by.ctp', 'remoteObject'],
        ];
    }

    /**
     * @dataProvider serverRowProvider
     */
    public function testServerPreviewRowsEscapeRemoteIds($template, $builder)
    {
        $html = $this->render($template, ['object' => $this->$builder('id')]);
        $this->assertEscaped($html);
        foreach ($this->handlers($html) as $handler) {
            if (strpos($handler, 'pivotObjectReferences') === 0) {
                $this->assertSame(
                    'pivotObjectReferences("\/servers\/previewEvent\/1\/2", ' . json_encode(self::REMOTE) . ')',
                    $handler
                );
            }
        }
    }

    public function testOvermindPreviewCopiesTheRemoteUuidAsAString()
    {
        $object = $this->remoteObject('uuid') + ['id' => 1, 'objectType' => 'object'];
        $html = $this->render(
            'Themed/Overmind/Elements/Servers/View/preview_object.ctp',
            ['data' => ['Event' => ['id' => 1], 'objects' => [$object]]]
        );
        $this->assertEscaped($html);
        $copies = array_values(array_filter($this->handlers($html), function ($handler) {
            return strpos($handler, 'copyValueToClipboard(') === 0;
        }));
        $this->assertCount(1, $copies);
        $this->assertStringStartsWith('copyValueToClipboard(' . json_encode(self::REMOTE) . ', ', $copies[0]);
    }

    public function analystDataProvider()
    {
        return [
            'none yet' => [[]],
            'with a note' => [['Note' => [['uuid' => 'n']]]],
        ];
    }

    /**
     * @dataProvider analystDataProvider
     */
    public function testOvermindPreviewAnalystDataOpensTheRemoteUuidAsAString(array $data)
    {
        $html = $this->render(
            'Themed/Overmind/Elements/genericElementsBS5/IndexTable/Fields/analyst_data_badges.ctp',
            [
                'baseurl' => '/misp',
                'row' => $this->remoteAttribute('uuid') + $data,
                'field' => [
                    'note_path' => 'Note',
                    'opinion_path' => 'Opinion',
                    'relationship_path' => 'Relationship',
                    'relationship_inbound_path' => 'RelationshipInbound',
                    'uuid_path' => 'uuid',
                    'object_type' => 'Attribute',
                ],
            ]
        );
        $this->assertStringNotContainsString('<i>', $html);
        $url = '/misp/analystData/viewForObject/Attribute/' . rawurlencode(self::REMOTE);
        $this->assertSame(
            ['event.stopPropagation(); openModal(' . json_encode($url) . ');'],
            $this->handlers($html)
        );
    }
}
