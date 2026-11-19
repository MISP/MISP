<?php
use PHPUnit\Framework\TestCase;

class AttributeFastLookupControllerDiscoveryTest extends TestCase
{
    /**
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testDiscoveryDoesNotReplaceOtherSuitesFrameworkStubs(): void
    {
        require_once __DIR__ . '/AttributeFastLookupControllerTest.php';

        foreach (['Configure', 'AppController', 'CakeResponse', 'HttpException'] as $class) {
            $this->assertFalse(class_exists($class, false), "$class must load only when isolated controller tests execute.");
        }
    }
}
