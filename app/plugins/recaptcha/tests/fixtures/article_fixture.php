<?php
/**
 * Copyright 2009-2010, Cake Development Corporation (http://cakedc.com)
 *
 * Licensed under The MIT License
 * Redistributions of files must retain the above copyright notice.
 *
 * @copyright Copyright 2009-2010, Cake Development Corporation (http://cakedc.com)
 * @license MIT License (http://www.opensource.org/licenses/mit-license.php)
 */

/**
 * Article Fixture
 *
 * @package recaptcha
 * @subpackage recaptcha.tests.fixtures
 */
class ArticleFixture extends CakeTestFixture {

/**
 * name property
 *
 * @var string
 */
	public $name = 'Article';

/**
 * fields property
 *
 * @var array
 */
	public $fields = array(
		'id' => array('type' => 'integer', 'key' => 'primary'),
		'title' => array('type' => 'string', 'null' => false),
		'comments' => array('type' => 'integer', 'null' => false, 'default' => '0'));

/**
 * records property
 *
 * @var array
 */
	public $records = array(
		array('title' => 'First Article', 'comments' => 2),
		array('title' => 'Second Article', 'comments' => 0));
}
