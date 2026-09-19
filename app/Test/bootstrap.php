<?php
/**
 * Shared bootstrap for MISP PHP test suites.
 *
 * Unit tests get framework stubs instead of a CakePHP bootstrap, so they run
 * with no database, no Redis and no HTTP.
 */
require_once __DIR__ . "/../Vendor/autoload.php";
require_once __DIR__ . "/Support/FrameworkStubs.php";

\MispTest\Support\FrameworkStubs::install();
