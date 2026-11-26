<?php
/**
 * The top-correlation and occurrence regeneration actions start work, so the
 * admin views must reach them with a POST form, never a plain link.
 */

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/ViewTemplateHarness.php';

class CorrelationGenerationLinksFormHelper
{
    public function postLink($title, $url, $options = [])
    {
        return sprintf('<form method="post" action="%s"></form><a href="#">%s</a>', $url, $title);
    }
}

class CorrelationGenerationLinksTest extends TestCase
{
    private function topBarOf($template, array $vars)
    {
        $view = new ViewTemplateHarness();
        $view->helpers['Form'] = new CorrelationGenerationLinksFormHelper();
        $view->render($template, $vars + ['baseurl' => '', 'data' => [], 'ajax' => true, 'title_for_layout' => '']);
        foreach ($view->elements as $element) {
            if ($element[0] === 'genericElements/IndexTable/index_table') {
                return $element[1]['data']['top_bar']['children'];
            }
        }
        $this->fail('The index table was not rendered');
    }

    private function assertPostsTo(array $groups, $action)
    {
        $plain = [];
        $posted = false;
        foreach ($groups as $group) {
            foreach ($group['children'] ?? [] as $child) {
                if (!empty($child['url']) && strpos($child['url'], $action) !== false) {
                    $plain[] = $child['url'];
                }
                if (!empty($child['html']) && strpos($child['html'], 'method="post"') !== false
                    && strpos($child['html'], $action) !== false) {
                    $posted = true;
                }
            }
        }
        $this->assertSame([], $plain, 'Plain link to ' . $action);
        $this->assertTrue($posted, 'No POST form for ' . $action);
    }

    public function testTopCorrelationsRegeneratesByPost()
    {
        $groups = $this->topBarOf('Correlations/top.ctp', ['age' => 1, 'age_unit' => 'h', 'onDemandEngine' => false, 'menuData' => []]);
        $this->assertPostsTo($groups, 'generateTopCorrelations');
    }

    public function testOverCorrelationsRegeneratesByPost()
    {
        $groups = $this->topBarOf('Correlations/over_correlations.ctp', ['scope' => 'all', 'menuData' => []]);
        $this->assertPostsTo($groups, 'generateOccurrences');
    }
}
