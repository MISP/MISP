<?php
/**
 * Tags in a remote server's or a feed's event preview are shown without
 * being saved, so Tag's colour validation never ran on them: what goes into
 * their style attribute must be a colour.
 */

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/ViewTemplateHarness.php';
require_once __DIR__ . '/../View/Helper/TextColourHelper.php';

class PreviewTagColourTest extends TestCase
{
    const COLOUR = 'red;border:0';

    /** @var ViewTemplateHarness */
    private $view;

    protected function setUp(): void
    {
        $this->view = new ViewTemplateHarness();
        $this->view->helpers['TextColour'] = new TextColourHelper();
        Configure::write('MISP.tagging', true);
    }

    protected function tearDown(): void
    {
        Configure::write('MISP.tagging', null);
    }

    private function tag($colour)
    {
        return ['id' => 1, 'name' => 'tlp:clear', 'colour' => $colour];
    }

    private function event($colour)
    {
        return [
            'Event' => [
                'id' => 2,
                'uuid' => '5bd7f6e0-0000-4000-8000-000000000002',
                'info' => 'remote',
                'date' => '2026-11-16',
                'threat_level_id' => 1,
                'analysis' => 0,
                'distribution' => 1,
                'published' => 1,
                'timestamp' => 0,
            ],
            'Orgc' => ['name' => 'remote'],
            'Org' => ['name' => 'remote'],
            'Tag' => [$this->tag($colour)],
        ];
    }

    private function previewVars($colour)
    {
        return [
            'baseurl' => '',
            'event' => $this->event($colour),
            'eventDescriptions' => ['threat_level_id' => ['desc' => ''], 'analysis' => ['desc' => '']],
            'threatLevels' => [1 => 'High'],
            'analysisLevels' => [0 => 'Initial'],
            'distributionLevels' => [1 => 'This community only'],
            'feed' => ['Feed' => ['id' => 3, 'name' => 'feed', 'provider' => 'provider']],
            'server' => ['Server' => ['id' => 4, 'name' => 'server', 'url' => 'https://example.org']],
            'me' => ['Role' => ['perm_site_admin' => false]],
        ];
    }

    /** The Tags row's HTML, which the page hands to the meta table element. */
    private function tagsRow($template, $colour)
    {
        $this->view->render($template, $this->previewVars($colour));
        foreach ($this->view->elements as [$name, $data]) {
            foreach ($data['table_data'] ?? [] as $row) {
                if ($row['key'] === 'Tags') {
                    return $row['html'];
                }
            }
        }
        $this->fail("$template: no Tags row");
    }

    public function previews()
    {
        return [
            'feed event' => ['Feeds/preview_event.ctp'],
            'server event' => ['Servers/preview_event.ctp'],
        ];
    }

    /**
     * @dataProvider previews
     */
    public function testEventTags($template)
    {
        $html = $this->tagsRow($template, self::COLOUR);
        $this->assertStringNotContainsString('border:0', $html);
        $this->assertStringContainsString('background-color:#ffffff;', $html);

        $this->view->elements = [];
        $this->assertStringContainsString('background-color:#3300ff;', $this->tagsRow($template, '#3300ff'));
    }

    public function sources()
    {
        return [
            'server' => ['server', ['Server' => ['id' => 4]]],
            'feed' => ['feed', ['Feed' => ['id' => 3]]],
        ];
    }

    /**
     * @dataProvider sources
     */
    public function testAttributeTags($key, $source)
    {
        $vars = [
            'baseurl' => '',
            'attributeId' => 5,
            'isAclTagger' => false,
            'tagAccess' => false,
            $key => $source,
        ];
        $html = $this->view->render('Elements/ajaxAttributeTags.ctp',
            $vars + ['attributeTags' => [['Tag' => $this->tag(self::COLOUR)]]]);
        $this->assertStringNotContainsString('border:0', $html);
        $this->assertStringContainsString('background-color:#ffffff;', $html);

        $html = $this->view->render('Elements/ajaxAttributeTags.ctp',
            $vars + ['attributeTags' => [['Tag' => $this->tag('#3300ff')]]]);
        $this->assertStringContainsString('background-color:#3300ff;', $html);
    }

    public function testOvermindBadge()
    {
        $render = function ($colour) {
            return $this->view->render('Themed/Overmind/Elements/genericElementsBS5/Badges/tag.ctp', [
                'tag' => $this->tag($colour),
                'local' => false,
                'hiddenClass' => '',
            ]);
        };

        $html = $render(self::COLOUR);
        $this->assertStringNotContainsString('border:0', $html);
        $this->assertStringContainsString('background-color:#0088cc;', $html);
        $this->assertStringContainsString('background-color:#3300ff;', $render('#3300ff'));
    }
}
