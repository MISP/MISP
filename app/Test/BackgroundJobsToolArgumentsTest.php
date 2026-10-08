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

require_once __DIR__ . '/../Lib/Tools/BackgroundJobsTool.php';

/**
 * A job's arguments become the argv of the `cake` console process that runs it,
 * and ShellDispatcher::_parsePaths() picks its path switches out of anywhere in
 * that argv. An argument carrying user input must therefore never be able to
 * spell one, or the caller chooses the application root of the worker process.
 */
class BackgroundJobsToolArgumentsTest extends TestCase
{
    /**
     * @param array $args
     * @return bool
     */
    private function validate(array $args)
    {
        $tool = (new ReflectionClass('BackgroundJobsTool'))->newInstanceWithoutConstructor();
        $method = new ReflectionMethod('BackgroundJobsTool', 'validateArgs');
        $method->setAccessible(true);
        return $method->invoke($tool, $args);
    }

    public function testOrdinaryArgumentsPass()
    {
        $this->assertTrue($this->validate(['contactemail', 7, 'Please get in touch.', true, 195, 42]));
        $this->assertTrue($this->validate(['enrichment', 195, 7, '["dns","urlhaus"]', 42]));
        $this->assertTrue($this->validate([]));
    }

    public function testValuesThatMerelyContainASwitchPass()
    {
        // Only a whole argument is a switch to the dispatcher, so free text that
        // happens to mention one stays deliverable.
        $this->assertTrue($this->validate(['contactemail', 7, 'see the -working directory', true, 195, 42]));
        $this->assertTrue($this->validate(['contactemail', 7, '--app-store link', true, 195, 42]));
    }

    public function testEveryReservedSwitchIsRefused()
    {
        foreach (BackgroundJobsTool::RESERVED_ARGUMENTS as $switch) {
            try {
                $this->validate(['contactemail', 7, $switch, 'phar:///tmp/evil.gif', 195, 42]);
                $this->fail("Reserved argument $switch was accepted.");
            } catch (InvalidArgumentException $e) {
                $this->assertStringContainsString($switch, $e->getMessage());
            }
        }
    }

    public function testNonStringArgumentsAreLeftAlone()
    {
        $this->assertTrue($this->validate([1, 2.5, true, null, ['-app']]));
    }
}
