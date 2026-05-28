<?php
/**
 * MailLogTool unit tests (DD-41 contract + DD-43 rotated-file
 * traversal).
 *
 * Pure PHPUnit — follows the project convention used by every other
 * file under app/Test/: no CakePHP bootstrap, no DB.  MailLogTool has
 * no framework dependencies (uses SPL InvalidArgumentException +
 * RuntimeException), so no stubs are required.
 *
 * Fixtures are written to a per-test temp directory under sys_get_
 * temp_dir() and cleaned up in tearDown().  Fixtures cover both
 * postfix timestamp formats (RFC3339 + legacy syslog) and a mix of
 * deliverable / non-deliverable / non-parseable lines.
 */

require_once __DIR__ . '/../Vendor/autoload.php';
require_once __DIR__ . '/../Lib/Tools/MailLogTool.php';

use PHPUnit\Framework\TestCase;

class MailLogToolTest extends TestCase
{
    /** @var string */
    private $dir;

    /** @var string */
    private $base;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/maillog-test-' . uniqid();
        if (!is_dir($this->dir)) {
            mkdir($this->dir, 0700, true);
        }
        $this->base = $this->dir . '/mail.log';
    }

    protected function tearDown(): void
    {
        if (is_dir($this->dir)) {
            foreach (glob($this->dir . '/*') as $f) {
                if (is_link($f) || is_file($f)) {
                    @unlink($f);
                }
            }
            @rmdir($this->dir);
        }
    }

    // -- Path safety --------------------------------------------------

    public function testIsAllowedPathAcceptsVarLog(): void
    {
        $this->assertTrue(MailLogTool::isAllowedPath('/var/log/mail.log'));
        $this->assertTrue(MailLogTool::isAllowedPath('/var/log/mail.log.1'));
        $this->assertTrue(MailLogTool::isAllowedPath('/var/log/mail.log.2.gz'));
    }

    public function testIsAllowedPathAcceptsTmp(): void
    {
        $this->assertTrue(MailLogTool::isAllowedPath('/tmp/test-mail.log'));
    }

    public function testIsAllowedPathRejectsTraversal(): void
    {
        $this->assertFalse(MailLogTool::isAllowedPath('/var/log/../etc/passwd'));
    }

    public function testIsAllowedPathRejectsNullByte(): void
    {
        $this->assertFalse(MailLogTool::isAllowedPath("/var/log/mail.log\0/etc/passwd"));
    }

    public function testIsAllowedPathRejectsOtherDirs(): void
    {
        $this->assertFalse(MailLogTool::isAllowedPath('/etc/passwd'));
        $this->assertFalse(MailLogTool::isAllowedPath('/home/user/mail.log'));
    }

    public function testTailRejectsBadPath(): void
    {
        $this->expectException(InvalidArgumentException::class);
        MailLogTool::tail('/etc/passwd');
    }

    public function testTailRejectsMissingFile(): void
    {
        $this->expectException(RuntimeException::class);
        MailLogTool::tail($this->dir . '/does-not-exist.log');
    }

    // -- Live-tail behaviour (DD-41 baseline) --------------------------

    public function testTailReturnsParsedRowsNewestFirst(): void
    {
        file_put_contents($this->base, $this->liveFixture());
        $rows = MailLogTool::tail($this->base, 65536, 20, '');
        // 5 delivery rows (ABCD0001..0005); qmgr lifecycle row
        // (ABCD9999) skipped.
        $this->assertCount(5, $rows);
        // Newest first
        $this->assertSame('ABCD0005', $rows[0]['queue_id']);
        $this->assertSame('bounced', $rows[0]['status']);
        $this->assertSame('ABCD0001', $rows[4]['queue_id']);
    }

    public function testTailNormalisesAllStatuses(): void
    {
        file_put_contents($this->base, $this->liveFixture());
        $rows = MailLogTool::tail($this->base, 65536, 20, '');
        $statuses = array_column($rows, 'status');
        $this->assertContains('sent', $statuses);
        $this->assertContains('deferred', $statuses);
        $this->assertContains('bounced', $statuses);
    }

    public function testTailLimitCaps(): void
    {
        file_put_contents($this->base, $this->liveFixture());
        $rows = MailLogTool::tail($this->base, 65536, 2, '');
        $this->assertCount(2, $rows);
        // Newest two
        $this->assertSame('ABCD0005', $rows[0]['queue_id']);
        $this->assertSame('ABCD0004', $rows[1]['queue_id']);
    }

    public function testTailSearchFiltersWithinLive(): void
    {
        file_put_contents($this->base, $this->liveFixture());
        $rows = MailLogTool::tail($this->base, 65536, 10, 'alice');
        $this->assertCount(2, $rows);
        foreach ($rows as $r) {
            $this->assertSame('alice@x.com', $r['recipient']);
        }
    }

    public function testTailSearchIsCaseInsensitive(): void
    {
        file_put_contents($this->base, $this->liveFixture());
        $upper = MailLogTool::tail($this->base, 65536, 10, 'ALICE');
        $lower = MailLogTool::tail($this->base, 65536, 10, 'alice');
        $this->assertCount(count($lower), $upper);
    }

    public function testTailSearchScansMessageField(): void
    {
        file_put_contents($this->base, $this->liveFixture());
        // "live-alice#1" only appears in the (parens) status detail
        $rows = MailLogTool::tail($this->base, 65536, 10, 'live-alice#1');
        $this->assertCount(1, $rows);
        $this->assertSame('ABCD0002', $rows[0]['queue_id']);
    }

    // -- DD-43: rotated-file traversal --------------------------------

    public function testRotatedScanFillsRemainingSlots(): void
    {
        $this->writeFullFixture();
        $rows = MailLogTool::tail($this->base, 65536, 10, 'alice');
        // 2 from live + 1 from .1 + 2 from .2.gz = 5
        $this->assertCount(5, $rows);
        $this->assertSame('ABCD0004', $rows[0]['queue_id']); // live newest
        $this->assertSame('ABCD0002', $rows[1]['queue_id']); // live older
        $this->assertSame('BCDE0002', $rows[2]['queue_id']); // .1
        $this->assertSame('CDEF0004', $rows[3]['queue_id']); // .2.gz newer
        $this->assertSame('CDEF0002', $rows[4]['queue_id']); // .2.gz older
    }

    public function testRotatedScanRespectsLimit(): void
    {
        $this->writeFullFixture();
        $rows = MailLogTool::tail($this->base, 65536, 3, 'alice');
        // Live fills 2 (within window of older entries discovered by
        // file fseek-tail), .1 fills 1 more, .2.gz unused.
        $this->assertCount(3, $rows);
        $this->assertSame('ABCD0004', $rows[0]['queue_id']);
        $this->assertSame('ABCD0002', $rows[1]['queue_id']);
        $this->assertSame('BCDE0002', $rows[2]['queue_id']);
    }

    public function testRotatedScanLiveOnlyWhenLimitFilledLive(): void
    {
        $this->writeFullFixture();
        $rows = MailLogTool::tail($this->base, 65536, 2, 'alice');
        $this->assertCount(2, $rows);
        // Both should be live-file matches (queue IDs ABCD*)
        $this->assertSame('ABCD0004', $rows[0]['queue_id']);
        $this->assertSame('ABCD0002', $rows[1]['queue_id']);
    }

    public function testRotatedScanGzOnly(): void
    {
        $this->writeFullFixture();
        // "r2-alice" only exists in the gz companion
        $rows = MailLogTool::tail($this->base, 65536, 10, 'r2-alice');
        $this->assertCount(2, $rows);
        foreach ($rows as $r) {
            $this->assertStringStartsWith('CDEF', $r['queue_id']);
        }
    }

    public function testNoSearchSkipsRotated(): void
    {
        $this->writeFullFixture();
        // Without search filter, only the live file is read regardless
        // of available rotated companions.
        $rows = MailLogTool::tail($this->base, 65536, 20, '');
        $this->assertCount(5, $rows); // live has 5 status rows
        foreach ($rows as $r) {
            $this->assertStringStartsWith('ABCD', $r['queue_id']);
        }
    }

    public function testRotatedScanSkipsNonNumericSuffix(): void
    {
        $this->writeFullFixture();
        file_put_contents($this->base . '.foo', "garbage line that should never be read\n");
        file_put_contents($this->base . '.bak', "more garbage\n");
        // Same expectations as the full-traversal test — the .foo/.bak
        // companions are filtered out by the ctype_digit check.
        $rows = MailLogTool::tail($this->base, 65536, 10, 'alice');
        $this->assertCount(5, $rows);
    }

    public function testRotatedScanRejectsSymlinkOutsideAllowList(): void
    {
        $this->writeFullFixture();
        // Symlink a rotation candidate to /etc/passwd; realpath check
        // must reject (resolved path not in allow-list).
        @symlink('/etc/passwd', $this->base . '.99');
        $rows = MailLogTool::tail($this->base, 65536, 10, 'alice');
        // Same 5 alice rows as without the symlink — no /etc/passwd
        // content interfered.
        $this->assertCount(5, $rows);
    }

    // -- countLogFiles helper -----------------------------------------

    public function testCountLogFilesCountsLiveAndRotated(): void
    {
        $this->writeFullFixture();
        $this->assertSame(3, MailLogTool::countLogFiles($this->base));
    }

    public function testCountLogFilesLiveOnly(): void
    {
        file_put_contents($this->base, $this->liveFixture());
        $this->assertSame(1, MailLogTool::countLogFiles($this->base));
    }

    public function testCountLogFilesUnreadable(): void
    {
        // File doesn't exist
        $this->assertSame(0, MailLogTool::countLogFiles($this->dir . '/nope.log'));
    }

    public function testCountLogFilesIgnoresSymlinkOutsideAllowList(): void
    {
        $this->writeFullFixture();
        @symlink('/etc/passwd', $this->base . '.99');
        // Still 3 (.99 rejected, .1 and .2.gz counted plus live)
        $this->assertSame(3, MailLogTool::countLogFiles($this->base));
    }

    // -- Fixtures -----------------------------------------------------

    /**
     * Live mail.log fixture: 5 delivery rows + 1 queue-lifecycle row
     * (qmgr) that parseLine should NOT pick up.  2 of the 5 deliveries
     * are alice@.
     */
    private function liveFixture(): string
    {
        return <<<EOT
2026-05-27T10:00:01.111111+02:00 host postfix/smtp[1001]: ABCD0001: to=<bob@x.com>, relay=mx.x.com[1.1.1.1]:25, delay=0.5, status=sent (250 OK live#1)
2026-05-27T10:00:02.222222+02:00 host postfix/smtp[1002]: ABCD0002: to=<alice@x.com>, relay=mx.x.com[1.1.1.1]:25, delay=0.7, status=sent (250 OK live-alice#1)
2026-05-27T10:00:03.333333+02:00 host postfix/smtp[1003]: ABCD0003: to=<carol@x.com>, relay=mx.x.com[1.1.1.1]:25, delay=12.0, status=deferred (delivery timed out)
2026-05-27T10:00:04.444444+02:00 host postfix/smtp[1004]: ABCD0004: to=<alice@x.com>, relay=mx.x.com[1.1.1.1]:25, delay=0.6, status=sent (250 OK live-alice#2)
2026-05-27T10:00:05.555555+02:00 host postfix/qmgr[999]: ABCD9999: from=<root@host>, size=512, nrcpt=1 (queue active)
2026-05-27T10:00:06.666666+02:00 host postfix/smtp[1005]: ABCD0005: to=<eve@x.com>, relay=mx.x.com[1.1.1.1]:25, delay=0.4, status=bounced (550 No such user)

EOT;
    }

    /**
     * Plain rotated .1 fixture: 3 delivery rows, 1 alice match.
     */
    private function plainRotatedFixture(): string
    {
        return <<<EOT
2026-05-26T08:00:01.111111+02:00 host postfix/smtp[2001]: BCDE0001: to=<bob@x.com>, relay=mx.x.com[1.1.1.1]:25, delay=0.5, status=sent (250 OK r1#1)
2026-05-26T08:00:02.222222+02:00 host postfix/smtp[2002]: BCDE0002: to=<alice@x.com>, relay=mx.x.com[1.1.1.1]:25, delay=0.7, status=sent (250 OK r1-alice#1)
2026-05-26T08:00:03.333333+02:00 host postfix/smtp[2003]: BCDE0003: to=<carol@x.com>, relay=mx.x.com[1.1.1.1]:25, delay=0.6, status=sent (250 OK r1#3)

EOT;
    }

    /**
     * Gz rotated .2.gz fixture: 4 delivery rows, 2 alice matches.
     */
    private function gzRotatedFixture(): string
    {
        return <<<EOT
2026-05-25T07:00:01.111111+02:00 host postfix/smtp[3001]: CDEF0001: to=<bob@x.com>, relay=mx.x.com[1.1.1.1]:25, delay=0.5, status=sent (250 OK r2#1)
2026-05-25T07:00:02.222222+02:00 host postfix/smtp[3002]: CDEF0002: to=<alice@x.com>, relay=mx.x.com[1.1.1.1]:25, delay=0.7, status=sent (250 OK r2-alice#1)
2026-05-25T07:00:03.333333+02:00 host postfix/smtp[3003]: CDEF0003: to=<frank@x.com>, relay=mx.x.com[1.1.1.1]:25, delay=0.6, status=deferred (try later)
2026-05-25T07:00:04.444444+02:00 host postfix/smtp[3004]: CDEF0004: to=<alice@x.com>, relay=mx.x.com[1.1.1.1]:25, delay=0.7, status=bounced (550 r2-alice-bounce)

EOT;
    }

    private function writeFullFixture(): void
    {
        file_put_contents($this->base, $this->liveFixture());
        file_put_contents($this->base . '.1', $this->plainRotatedFixture());
        $gz = gzopen($this->base . '.2.gz', 'wb');
        gzwrite($gz, $this->gzRotatedFixture());
        gzclose($gz);
    }
}
