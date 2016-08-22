<?php

/**
 * View Group Test for CakeResque
 *
 * PHP versions 5
 *
 * Licensed under The MIT License
 * Redistributions of files must retain the above copyright notice.
 *
 * @author        Wan Qi Chen <kami@kamisama.me>
 * @copyright     Copyright 2012, Wan Qi Chen <kami@kamisama.me>
 * @link          http://cakeresque.kamisama.me
 * @package       CakeResque
 * @subpackage	 CakeResque.Lib
 * @since         1.2.0
 * @license       MIT License (http://www.opensource.org/licenses/mit-license.php)
 **/

/**
 * AllCakeResqueTest class
 *
 * @package 		CakeResque
 * @subpackage 	CakeResque.Test.Case
 */
class AllCakeResqueTest extends CakeTestSuite {

	public static function suite() {
		$suite = new CakeTestSuite('CakeResque test');
		$path = CakePlugin::path('CakeResque') . 'Test' . DS . 'Case' . DS;
		$suite->addTestDirectoryRecursive($path);

		return $suite;
	}
}
