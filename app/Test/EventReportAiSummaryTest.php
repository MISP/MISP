<?php
/**
 * EventReport::stripAiSummary() / mergeAiSummary() (AI UX P4.2): the AI
 * summary block of PRD §3.3 — a `# AI summary` heading on top, the summary,
 * a blank line and a visible delineator line of equals signs — is stripped
 * before the report is sent to the AI module, and the module's answer is
 * laid out again so that a re-run replaces the previous summary instead of
 * stacking on it. Both are pure static helpers.
 *
 * Pure PHPUnit, no CakePHP bootstrap, no DB (the app/Test convention).
 * EventReport.php only needs App::uses(), AppModel and the APP constant at
 * load time.
 */

require_once __DIR__ . '/../Vendor/autoload.php';

use PHPUnit\Framework\TestCase;

if (!defined('APP')) {
    define('APP', __DIR__ . '/../');
}
if (!class_exists('App', false)) {
    class App
    {
        public static function uses($class, $package)
        {
        }
    }
}
if (!class_exists('AppModel', false)) {
    class AppModel
    {
    }
}

require_once __DIR__ . '/../Model/EventReport.php';

class EventReportAiSummaryTest extends TestCase
{
    const HEADING = '# AI summary';
    const LINE = '==================';
    const ORIGINAL = "# Incident notes\n\nThe actor used **mimikatz** on host A.\n\n- ioc one\n- ioc two\n";

    /** The canonical stored layout: heading, summary, blank line, delineator, blank line, report. */
    private static function block($summary)
    {
        return self::HEADING . "\n" . $summary . "\n\n" . self::LINE . "\n";
    }

    private static function stored($summary, $report = self::ORIGINAL)
    {
        return self::block($summary) . "\n" . $report;
    }

    // --- strip -------------------------------------------------------------

    public function testStripLeavesContentWithoutABlockUntouched()
    {
        $this->assertSame(self::ORIGINAL, EventReport::stripAiSummary(self::ORIGINAL));
    }

    public function testStripOfTheCanonicalBlockGivesTheOriginalBack()
    {
        $this->assertSame(self::ORIGINAL, EventReport::stripAiSummary(self::stored('- one line')));
    }

    public function testStripAcceptsAModuleBlockWithoutTheBlankLineBeforeTheDelineator()
    {
        $sloppy = self::HEADING . "\n- a\n- b\n" . self::LINE . "\n" . self::ORIGINAL;
        $this->assertSame(self::ORIGINAL, EventReport::stripAiSummary($sloppy));
    }

    public function testStripToleratesHeadingCaseSpacingAndALongerLine()
    {
        $stored = "\n#  ai Summary  \nsummary\n\n" . str_repeat('=', 40) . "  \n\n\n" . self::ORIGINAL;
        $this->assertSame(self::ORIGINAL, EventReport::stripAiSummary($stored));
    }

    public function testStripNeedsTheHeadingOnTop()
    {
        // A report that merely contains a line of equals signs is the analyst's text.
        $userText = "Intro\n\n" . self::LINE . "\n\nbody\n";
        $this->assertSame($userText, EventReport::stripAiSummary($userText));
        $movedDown = "note above\n\n" . self::stored('x');
        $this->assertSame($movedDown, EventReport::stripAiSummary($movedDown));
    }

    public function testStripNeedsTheDelineator()
    {
        $headingOnly = self::HEADING . "\nsummary without a line\n\n" . self::ORIGINAL;
        $this->assertSame($headingOnly, EventReport::stripAiSummary($headingOnly));
        $tooShort = self::HEADING . "\nsummary\n\n=====\n\n" . self::ORIGINAL;
        $this->assertSame($tooShort, EventReport::stripAiSummary($tooShort));
    }

    public function testStripRemovesOnlyTheTopBlock()
    {
        $stored = self::stored('first', self::stored('second'));
        $this->assertSame(self::stored('second'), EventReport::stripAiSummary($stored));
    }

    public function testStripHandlesEmptyAndNull()
    {
        $this->assertSame('', EventReport::stripAiSummary(''));
        $this->assertSame('', EventReport::stripAiSummary(null));
    }

    // --- merge -------------------------------------------------------------

    public function testMergeStoresAFullRevisedReportInTheCanonicalLayout()
    {
        $returned = self::stored('- new');
        $this->assertSame($returned, EventReport::mergeAiSummary(self::ORIGINAL, $returned));
    }

    public function testMergeReplacesThePreviousBlockWithTheRevisedReport()
    {
        $merged = EventReport::mergeAiSummary(self::stored('- old'), self::stored('- new'));
        $this->assertSame(self::stored('- new'), $merged);
        $this->assertSame(1, substr_count($merged, self::HEADING));
        $this->assertSame(1, substr_count($merged, self::LINE));
        $this->assertStringNotContainsString('- old', $merged);
    }

    public function testMergeReLaysOutASloppyModuleBlock()
    {
        // No blank line before the delineator (a setext heading in Markdown) and stray blank lines.
        $sloppy = self::HEADING . "\n\n- a\n- b\n" . self::LINE . "\n\n\n\n" . self::ORIGINAL;
        $this->assertSame(self::stored("- a\n- b"), EventReport::mergeAiSummary(self::ORIGINAL, $sloppy));
    }

    public function testMergePutsABlockOnlyAnswerOnTopOfTheOriginal()
    {
        $merged = EventReport::mergeAiSummary(self::ORIGINAL, self::block('- only'));
        $this->assertSame(self::stored('- only'), $merged);
    }

    public function testMergeWrapsAnAnswerWithoutHeadingAndDelineator()
    {
        $merged = EventReport::mergeAiSummary(self::ORIGINAL, "  Two hosts, one tool.\n");
        $this->assertSame(self::stored('Two hosts, one tool.'), $merged);
    }

    public function testMergeDoesNotDoubleABareHeadingOnASummaryOnlyAnswer()
    {
        $merged = EventReport::mergeAiSummary(self::ORIGINAL, self::HEADING . "\nJust the text\n");
        $this->assertSame(self::stored('Just the text'), $merged);
    }

    public function testMergeDropsTheOldBlockWhenTheAnswerIsRawText()
    {
        $merged = EventReport::mergeAiSummary(self::stored('- old'), 'fresh');
        $this->assertSame(self::stored('fresh'), $merged);
    }

    public function testMergeOnAnEmptyOriginalIsJustTheBlock()
    {
        $this->assertSame(self::block('x'), EventReport::mergeAiSummary('', 'x'));
        $this->assertSame(self::block('x'), EventReport::mergeAiSummary(null, self::block('x')));
    }

    public function testStoredLayoutAlwaysKeepsABlankLineBeforeTheDelineator()
    {
        foreach (['text', self::HEADING . "\ntext\n" . self::LINE, self::HEADING . "\ntext\n" . self::LINE . "\n" . self::ORIGINAL] as $answer) {
            $merged = EventReport::mergeAiSummary(self::ORIGINAL, $answer);
            $this->assertStringContainsString("text\n\n" . self::LINE . "\n", $merged);
            $this->assertStringNotContainsString("text\n" . self::LINE, $merged);
        }
    }

    public function testRepeatedRunsKeepExactlyOneBlockAndTheBody()
    {
        $content = self::ORIGINAL;
        foreach (['first', 'second', 'third'] as $i => $summary) {
            // What the fake and the real module do: their block on top of what they were sent.
            $sent = EventReport::stripAiSummary($content);
            $this->assertSame(self::ORIGINAL, $sent, "run $i sends the original text");
            $content = EventReport::mergeAiSummary($content, self::block($summary) . "\n" . $sent);
            $this->assertSame(1, substr_count($content, self::HEADING), "run $i keeps one heading");
            $this->assertSame(1, substr_count($content, self::LINE), "run $i keeps one delineator");
            $this->assertStringContainsString($summary, $content);
            $this->assertStringEndsWith(self::ORIGINAL, $content);
        }
        $this->assertStringNotContainsString('first', $content);
        $this->assertStringNotContainsString('second', $content);
    }
}
