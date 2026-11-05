<?php

use PHPUnit\Framework\TestCase;

/**
 * The bootstrap's contract: every dependency-light source file must load
 * standalone under the shared stubs, with no database and no CakePHP
 * bootstrap. Later unit-test tranches (dashboard widgets, workflow modules,
 * export formats) all depend on this holding.
 *
 * Each file is probed in its own process because PHP cannot unload a class
 * once declared, so two files declaring the same symbol would collide.
 */
class BootstrapLoadabilityTest extends TestCase
{
    public function fileProvider(): array
    {
        $dirs = [
            APP . 'Lib/Tools',
            APP . 'Lib/Export',
            APP . 'Lib/Dashboard',
            APP . 'Model/WorkflowModules',
            APP . 'View/Helper',
        ];
        $cases = [];
        foreach ($dirs as $dir) {
            if (!is_dir($dir)) {
                continue;
            }
            $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir));
            foreach ($it as $f) {
                if ($f->isFile() && $f->getExtension() === 'php') {
                    $rel = str_replace(APP, '', $f->getPathname());
                    $cases[$rel] = [$f->getPathname()];
                }
            }
        }
        ksort($cases);
        return $cases;
    }

    /**
     * @dataProvider fileProvider
     */
    public function testFileLoadsStandalone(string $path): void
    {
        $cmd = sprintf(
            '%s -d error_reporting=0 %s %s 2>&1',
            escapeshellarg(PHP_BINARY),
            escapeshellarg(APP . 'Test/Support/load_probe.php'),
            escapeshellarg($path)
        );
        $out = trim((string)shell_exec($cmd));
        $this->assertSame(
            'OK',
            $out,
            sprintf(
                "%s does not load standalone.\n%s\n"
                . "Fix by adding its parent class to FrameworkStubs::loadRealParents(), "
                . "not by skipping the file.",
                str_replace(APP, '', $path),
                $out
            )
        );
    }
}
