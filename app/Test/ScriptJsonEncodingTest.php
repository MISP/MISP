<?php
/**
 * JSON printed into a <script> block is read by the HTML parser before the
 * script runs, so the values in it must not carry < > & ' " as they are.
 */

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/ViewTemplateHarness.php';
require_once __DIR__ . '/../Lib/Tools/JsonTool.php';

class ScriptJsonEncodingTest extends TestCase
{
    const TEXT = "a</p><!--b'\"&c";

    /** @var ViewTemplateHarness */
    private $view;

    protected function setUp(): void
    {
        $this->view = new ViewTemplateHarness();
    }

    /**
     * @param string $html
     * @param string $name
     * @return string[] the JSON assigned to `var $name` in each place
     */
    private function assigned($html, $name)
    {
        preg_match_all('/var ' . $name . ' = (.*);$/m', $html, $matches);
        $this->assertNotEmpty($matches[1], "no var $name");
        return $matches[1];
    }

    private function assertScriptSafe($json)
    {
        $this->assertNotRegExp('/[<>&\']/', $json);
    }

    public function testEncodeForScript()
    {
        $value = ['k' => self::TEXT, 'n' => [1, true, null]];
        $json = JsonTool::encodeForScript($value);

        $this->assertScriptSafe($json);
        $this->assertStringContainsString('"', $json);
        $this->assertSame($value, json_decode($json, true));
    }

    public function testObjectReferenceForm()
    {
        $event = [
            'Event' => ['id' => 1, 'info' => self::TEXT],
            'Attribute' => [[
                'id' => 2,
                'uuid' => '5bd7f6e0-0000-4000-8000-000000000002',
                'type' => 'text',
                'category' => 'Other',
                'value' => self::TEXT,
                'to_ids' => false,
            ]],
            'Object' => [],
        ];
        $html = $this->view->render('ObjectReferences/ajax/add.ctp', [
            'baseurl' => '',
            'objectId' => 3,
            'relationships' => [],
            'event' => $event,
        ]);

        [$json] = $this->assigned($html, 'targetEvent');
        $this->assertScriptSafe($json);
        $this->assertSame($event, json_decode($json, true));
    }

    public function testAnalystDataThread()
    {
        $note = [
            'uuid' => '5bd7f6e0-0000-4000-8000-000000000004',
            'note_type' => 0,
            'note_type_name' => 'Note',
            'note' => self::TEXT,
            'authors' => self::TEXT,
        ];
        $html = $this->view->render('Elements/genericElements/Analyst_data/thread.ctp', [
            'baseurl' => '',
            'seed' => 1,
            'me' => ['Role' => ['perm_modify' => true], 'Organisation' => ['uuid' => '5bd7f6e0-0000-4000-8000-000000000006']],
            'shortDist' => [0 => self::TEXT],
            'notes' => [$note],
            'opinions' => [],
            'relationships_outbound' => [],
            'relationships_inbound' => [],
            'allCounts' => ['notesOpinions' => 1, 'relationships_outbound' => 0, 'relationships_inbound' => 0],
            'object_type' => 'Event',
            'object_uuid' => '5bd7f6e0-0000-4000-8000-000000000005',
        ]);

        foreach (['shortDist', 'notes', 'relationships', 'relationships_inbound', 'relationship_related_object'] as $name) {
            foreach ($this->assigned($html, $name) as $json) {
                $this->assertScriptSafe($json);
            }
        }
        $this->assertSame([$note], json_decode($this->assigned($html, 'notes')[0], true));
    }

    public function testControllersPassScriptSafeJsonToViews()
    {
        $found = [];
        $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(__DIR__ . '/../Controller'));
        foreach ($files as $file) {
            if ($file->getExtension() !== 'php') {
                continue;
            }
            // Both are printed into <script> blocks as they are.
            if (preg_match_all("/set\('(passedArgs|tagJSON)',\s*json_encode\(/", file_get_contents($file), $m)) {
                $found[] = $file->getFilename() . ': ' . implode(', ', $m[1]);
            }
        }
        $this->assertSame([], $found);
    }
}
