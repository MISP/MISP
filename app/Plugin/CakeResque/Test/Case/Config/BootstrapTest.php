<?php
/**
 * Test the bootstrap file
 *
 * PHP versions 5
 *
 * Licensed under The MIT License
 * Redistributions of files must retain the above copyright notice.
 *
 * @author        Wan Qi Chen <kami@kamisama.me>
 * @copyright     Copyright 2013, Wan Qi Chen <kami@kamisama.me>
 * @link          http://cakeresque.kamisama.me
 * @package       CakeResque
 * @subpackage    CakeResque.Test.Case.Config
 * @since         2.2.0
 * @license       MIT License (http://www.opensource.org/licenses/mit-license.php)
 **/

/**
 * BootstrapTest class
 *
 * @package      CakeResque
 * @subpackage   CakeResque.Test.Case.Lib
 */

class BootstrapTest extends CakeTestCase {

	public function testBootstrapContainsAllMandatorySettings() {
		$s = Configure::read('CakeResque');

		$this->assertArrayHasKey('Redis', $s);
		$this->assertArrayHasKey('Worker', $s);
		$this->assertArrayHasKey('Resque', $s);
		$this->assertArrayHasKey('Log', $s);
		$this->assertArrayHasKey('Scheduler', $s);

		$this->assertArrayHasKey('host', $s['Redis']);
		$this->assertArrayHasKey('port', $s['Redis']);
		$this->assertArrayHasKey('database', $s['Redis']);
		$this->assertArrayHasKey('namespace', $s['Redis']);

		$this->assertArrayHasKey('queue', $s['Worker']);
		$this->assertArrayHasKey('interval', $s['Worker']);
		$this->assertArrayHasKey('workers', $s['Worker']);

		$this->assertArrayHasKey('handler', $s['Log']);
		$this->assertArrayHasKey('target', $s['Log']);

		$this->assertArrayHasKey('enabled', $s['Scheduler']);
	}
}
