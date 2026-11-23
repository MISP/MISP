<?php
/**
 * The review page of a merge, an import or an enrichment lists each object
 * reference with the uuid, name and meta-category of what it points to. They
 * come from another event, a module or an import file and must be escaped.
 */

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/ViewTemplateHarness.php';

class ResolvedMispFormatEscapingTest extends TestCase
{
    const FOREIGN = "x'\"<i>y";
    const TARGET = '5f6a1c2e-0b7d-4c8e-9a3f-2d1e0c9b8a70';

    private function event()
    {
        return [
            'Event' => ['id' => 1],
            'Attribute' => [],
            'Object' => [
                [
                    'uuid' => self::TARGET,
                    'name' => self::FOREIGN,
                    'meta-category' => self::FOREIGN,
                    'distribution' => 0,
                    'Attribute' => [],
                ],
                [
                    'uuid' => '0c3d2e1f-4a5b-4c6d-8e7f-9a0b1c2d3e4f',
                    'name' => 'file',
                    'meta-category' => 'file',
                    'distribution' => 0,
                    'Attribute' => [],
                    'ObjectReference' => [
                        ['relationship_type' => 'related-to', 'referenced_uuid' => self::TARGET],
                        ['relationship_type' => 'related-to', 'referenced_uuid' => self::FOREIGN],
                    ],
                ],
            ],
        ];
    }

    public function testObjectReferencesEscapeWhatTheyPointTo()
    {
        $html = (new ViewTemplateHarness())->render('Events/resolved_misp_format.ctp', [
            'title' => 'Merge',
            'event' => $this->event(),
            'baseurl' => '',
            'importComment' => '',
            'distributions' => [0 => 'Your organisation only'],
            'sgs' => [],
        ]);
        $references = substr($html, strpos($html, 'class="ObjectReference"'));
        $this->assertStringContainsString(
            '<span class="ReferencedUUID">' . self::TARGET . '</span> (' . h(self::FOREIGN) . ': ' . h(self::FOREIGN) . ')',
            $references
        );
        $this->assertStringContainsString('<span class="ReferencedUUID">' . h(self::FOREIGN) . '</span>', $references);
        $this->assertStringNotContainsString('<i>', $html);
    }
}
