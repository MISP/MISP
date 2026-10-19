<?php
if (!class_exists('App')) {
    class App
    {
        public static function uses($className, $location)
        {
        }
    }
}
require_once __DIR__ . '/../Lib/Tools/ValueIntelligence/ValueLabelPriority.php';

use PHPUnit\Framework\TestCase;

class ValueLabelPriorityTest extends TestCase
{
    public function testTheAssessmentIsShownUnlessSwitchedOff(): void
    {
        $this->assertTrue(ValueLabelPriority::showsAssessment(null));
        $this->assertTrue(ValueLabelPriority::showsAssessment(
            ['parameters' => ['context' => []]]
        ));
        $this->assertTrue(ValueLabelPriority::showsAssessment(
            ['parameters' => ['context' => ['show_assessment' => true]]]
        ));
        $this->assertFalse(ValueLabelPriority::showsAssessment(
            ['parameters' => ['context' => ['show_assessment' => false]]]
        ));
    }

    public function testOnlyAnExplicitFalseSwitchesItOff(): void
    {
        foreach ([0, '0', '', null, 'false'] as $value) {
            $this->assertTrue(ValueLabelPriority::showsAssessment(
                ['context' => ['show_assessment' => $value]]
            ), var_export($value, true));
        }
    }

    public function testParametersAloneAreRead(): void
    {
        $this->assertFalse(ValueLabelPriority::showsAssessment(
            ['context' => ['show_assessment' => false]]
        ));
    }
}
