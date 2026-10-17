<?php

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../Lib/Tools/BackgroundJobs/BackgroundJob.php';

/**
 * A failed job's `jobs` row carries one line of its stderr, which also holds
 * the audit-log echo, debug output and warnings written before the failure.
 */
class BackgroundJobErrorLineTest extends TestCase
{
    /**
     * @param string|null $stderr
     * @return string|null
     */
    private function errorLine($stderr)
    {
        $job = new BackgroundJob(['id' => 'x', 'command' => 'admin', 'error' => $stderr]);
        return $job->errorLine();
    }

    public function testCakeExceptionAfterLogEchoAndWarnings()
    {
        $stderr = "/var/www/MISP/app/tmp/logs/[1234]: {\"action\":\"add\",\"title\":\"Job created\"}\n"
            . "Warning Error: Undefined array key \"x\" in [/var/www/MISP/app/Model/Correlation.php, line 12]\n"
            . "Error: SQLSTATE[42000]: Syntax error or access violation: 1064 near ';' at line 1\n"
            . "#0 /var/www/MISP/app/Lib/cakephp/lib/Cake/Model/Datasource/DboSource.php(474): PDOStatement->execute(Array)\n"
            . "#1 {main}\n";
        $this->assertSame(
            "Error: SQLSTATE[42000]: Syntax error or access violation: 1064 near ';' at line 1",
            $this->errorLine($stderr)
        );
    }

    public function testPhpFatalError()
    {
        $stderr = "Deprecated Error: Creation of dynamic property in [/x.php, line 3]\n"
            . "PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 20480 bytes) in /x.php on line 9\n";
        $this->assertSame(
            'PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 20480 bytes) in /x.php on line 9',
            $this->errorLine($stderr)
        );
    }

    public function testTraceFramesAreNotTheError()
    {
        $stderr = "Error: Boom\n#0 /x.php(3): foo('Error: in an argument')\n#1 {main}";
        $this->assertSame('Error: Boom', $this->errorLine($stderr));
    }

    public function testWithoutAnErrorLineTheLastLineIsKept()
    {
        $this->assertSame('Killed', $this->errorLine("Fetching events.\nKilled\n\n"));
    }

    public function testNoStderr()
    {
        $this->assertNull($this->errorLine(null));
        $this->assertNull($this->errorLine(" \n"));
    }
}
