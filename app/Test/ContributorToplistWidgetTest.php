<?php

use PHPUnit\Framework\TestCase;

if (!class_exists('App', false)) {
    class App
    {
        public static function uses($class, $package = null)
        {
        }
    }
}

require_once __DIR__ . '/../Lib/Dashboard/Tools/WidgetToolkit.php';
require_once __DIR__ . '/../Lib/Dashboard/OrgContributionToplistWidget.php';
require_once __DIR__ . '/../Lib/Dashboard/UserContributionToplistWidget.php';

class ContributorToplistWidgetTest extends TestCase
{
    public function testOrganisationToplistAppliesSevenDayFilter(): void
    {
        $this->assertSevenDayFilter(new OrgContributionToplistWidget());
    }

    public function testUserToplistAppliesSevenDayFilter(): void
    {
        $this->assertSevenDayFilter(new UserContributionToplistWidget());
    }

    private function assertSevenDayFilter($widget): void
    {
        $method = new ReflectionMethod($widget, 'timeConditions');
        foreach ([7, '7', '7d'] as $days) {
            $earliest = strtotime('-7 days');
            $conditions = $method->invoke($widget, ['days' => $days]);
            $latest = strtotime('-7 days');
            $message = get_class($widget) . ' with days=' . json_encode($days);

            $this->assertArrayHasKey('Event.timestamp >=', $conditions, $message);
            $cutoff = $conditions['Event.timestamp >='];
            $this->assertGreaterThanOrEqual($earliest, $cutoff, $message);
            $this->assertLessThanOrEqual($latest, $cutoff, $message);
        }
    }
}
