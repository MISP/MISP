<?php

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../Vendor/autoload.php';

/**
 * Runs the real EventsController::__setIndexFilterConditions() body against a stub that only carries $paginate,
 * so the "eventinfo" filter can be exercised without a database.
 */
class EventIndexFilterEmptyPieceTest extends TestCase
{
    private static function stubClass()
    {
        $name = 'EventsControllerStubForIndexFilter';
        if (!class_exists($name, false)) {
            $source = file_get_contents(__DIR__ . '/../Controller/EventsController.php');
            $start = strpos($source, 'private function __setIndexFilterConditions(');
            $open = strpos($source, '{', $start);
            $depth = 0;
            for ($i = $open, $n = strlen($source); $i < $n; $i++) {
                if ($source[$i] === '{') {
                    $depth++;
                } elseif ($source[$i] === '}' && --$depth === 0) {
                    break;
                }
            }
            $method = substr($source, $start, $i - $start + 1);
            eval('class ' . $name . ' {
                public $paginate = array("conditions" => array("AND" => array()));
                ' . $method . '
            }');
        }
        return $name;
    }

    private function conditionsFor($eventinfo)
    {
        $class = self::stubClass();
        $stub = new $class();
        $urlparams = '';
        $method = new ReflectionMethod($class, '__setIndexFilterConditions');
        $method->setAccessible(true);
        $warnings = [];
        set_error_handler(function ($errno, $errstr) use (&$warnings) {
            $warnings[] = $errstr;
            return true;
        });
        try {
            $method->invokeArgs($stub, [['searcheventinfo' => $eventinfo], &$urlparams]);
        } finally {
            restore_error_handler();
        }
        return [$stub->paginate['conditions']['AND'], $warnings];
    }

    public function testEmptyPieceBetweenSeparatorsRaisesNoWarning()
    {
        list($conditions, $warnings) = $this->conditionsFor('11111||22222');
        $this->assertSame([], $warnings);
        $this->assertSame(
            [['OR' => [['lower(Event.info) LIKE' => '%11111%'], ['lower(Event.info) LIKE' => '%22222%']]]],
            $conditions
        );
    }

    public function testNegatedPiecesAroundAnEmptyPiece()
    {
        list($conditions, $warnings) = $this->conditionsFor('!Daily URLhaus Payload URLs||!Daily Incremental Feodotracker Import');
        $this->assertSame([], $warnings);
        $this->assertSame([
            ['lower(Event.info) NOT LIKE' => '%daily urlhaus payload urls%'],
            ['lower(Event.info) NOT LIKE' => '%daily incremental feodotracker import%'],
        ], $conditions);
    }

    public function testSeparatorsOnlyAddNoCondition()
    {
        list($conditions, $warnings) = $this->conditionsFor('||');
        $this->assertSame([], $warnings);
        $this->assertSame([], $conditions);
    }

    public function testPlainTermStillWorks()
    {
        list($conditions, $warnings) = $this->conditionsFor('Phishing');
        $this->assertSame([], $warnings);
        $this->assertSame([['OR' => [['lower(Event.info) LIKE' => '%phishing%']]]], $conditions);
    }
}
