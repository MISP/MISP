<?php
/**
 * Hover enrichment shows what a module returned, never saved and so never
 * validated: a link-type value becomes a link only when it is http(s).
 */

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/ViewTemplateHarness.php';

class HoverEnrichmentLinkTest extends TestCase
{
    const TEMPLATES = [
        'Default' => 'Attributes/ajax/hover_enrichment.ctp',
        'Overmind' => 'Themed/Overmind/Attributes/ajax/hover_enrichment.ctp',
    ];

    public function templates()
    {
        $cases = [];
        foreach (self::TEMPLATES as $theme => $template) {
            $cases[$theme] = [$template];
        }
        return $cases;
    }

    private function render($template, $value)
    {
        $view = new ViewTemplateHarness();
        return $view->render($template, [
            'persistent' => false,
            'results' => [
                'module' => [
                    'Attribute' => [['type' => 'link', 'value' => $value]],
                    'Object' => [[
                        'name' => 'url',
                        'Attribute' => [['type' => 'link', 'object_relation' => 'url', 'value' => $value]],
                    ]],
                ],
            ],
        ]);
    }

    /**
     * @dataProvider templates
     */
    public function testHttpLinkIsLinked($template)
    {
        $html = $this->render($template, 'https://example.org/a?b=1&c=2');

        $this->assertSame(2, substr_count($html, '<a href="https://example.org/a?b=1&amp;c=2"'));
    }

    /**
     * @dataProvider templates
     */
    public function testOtherSchemeIsText($template)
    {
        $html = $this->render($template, 'ftp://example.org/a');

        $this->assertStringNotContainsString('<a ', $html);
        $this->assertSame(2, substr_count($html, 'ftp://example.org/a'));
    }
}
