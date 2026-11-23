<?php
if (!class_exists('App')) {
    class App
    {
        public static function uses($className, $location)
        {
        }
    }
}
if (!function_exists('__')) {
    function __($singular, $args = null)
    {
        $arguments = array_slice(func_get_args(), 1);
        return empty($arguments) ? $singular : vsprintf($singular, $arguments);
    }
}
require_once __DIR__ . '/../Lib/Tools/OnboardingTour.php';

use PHPUnit\Framework\TestCase;

class OnboardingTourTest extends TestCase
{
    /**
     * @param array $denied [[controller, action], ...]
     * @return array The parts of the Investigate a value section, by id
     */
    private function investigateParts(array $denied = [])
    {
        $canAccess = function ($controller, $action) use ($denied) {
            return !in_array([$controller, $action], $denied, true);
        };
        foreach (OnboardingTour::sections($canAccess, 1) as $section) {
            if ($section['id'] !== 'investigate-value') {
                continue;
            }
            $parts = [];
            foreach ($section['steps'] as $step) {
                $parts[$step['groupId']][] = $step;
            }
            return $parts;
        }
        return [];
    }

    public function testWorkspaceAndSavedGraphsAreTwoParts()
    {
        $parts = $this->investigateParts();
        $this->assertArrayHasKey('workspace', $parts);
        $this->assertArrayHasKey('saved-graphs', $parts);
        $this->assertArrayNotHasKey('workspaces', $parts);
        $this->assertSame('Your workspace', $parts['workspace'][0]['group']);
        $this->assertSame('Saved graphs', $parts['saved-graphs'][0]['group']);
    }

    public function testWorkspacePartNeedsTheRightToAddToACollection()
    {
        $parts = $this->investigateParts([['collectionElements', 'addItems']]);
        $this->assertArrayNotHasKey('workspace', $parts);
        $this->assertArrayHasKey('saved-graphs', $parts);
    }

    public function testSavedGraphsPartNeedsTheRightToViewGraphs()
    {
        $parts = $this->investigateParts([['analystGraphs', 'view']]);
        $this->assertArrayHasKey('workspace', $parts);
        $this->assertArrayNotHasKey('saved-graphs', $parts);
    }

    public function testEveryStepSaysSomethingAndAClickStepPointsAtSomething()
    {
        $parts = $this->investigateParts();
        foreach (['workspace', 'saved-graphs'] as $id) {
            foreach ($parts[$id] as $i => $step) {
                $where = $id . ' step ' . ($i + 1);
                $this->assertNotEmpty($step['title'], $where);
                $this->assertNotEmpty($step['body'], $where);
                if (($step['advance'] ?? null) === 'click') {
                    $this->assertNotEmpty($step['anchor'], $where);
                }
                foreach (['pageMatch', 'skipIf', 'skipUnless'] as $key) {
                    if (isset($step[$key])) {
                        $this->assertNotFalse(@preg_match('#' . $step[$key] . '#', ''), $where . ' ' . $key);
                    }
                }
            }
        }
    }

    public function testCollectionStepsMatchACollectionPage()
    {
        $this->assertSame(1, preg_match('#' . OnboardingTour::COLLECTION_VIEW_MATCH . '#', '/collections/view/253'));
        $this->assertSame(1, preg_match('#' . OnboardingTour::COLLECTION_VIEW_MATCH . '#', '/collections/view/334fe088-1b7d-481f-97b1-e8afbb21bfcb'));
        $this->assertSame(0, preg_match('#' . OnboardingTour::COLLECTION_VIEW_MATCH . '#', '/collections/index'));
    }
}
