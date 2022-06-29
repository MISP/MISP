<?php
/**
 * AppShell file
 *
 * PHP 5
 *
 * CakePHP(tm) : Rapid Development Framework (http://cakephp.org)
 * Copyright 2005-2012, Cake Software Foundation, Inc. (http://cakefoundation.org)
 *
 * Licensed under The MIT License
 * Redistributions of files must retain the above copyright notice.
 *
 * @copyright     Copyright 2005-2012, Cake Software Foundation, Inc. (http://cakefoundation.org)
 * @link          http://cakephp.org CakePHP(tm) Project
 * @since         CakePHP(tm) v 2.0
 * @license       MIT License (http://www.opensource.org/licenses/mit-license.php)
 */

App::uses('AppModel', 'Model');

/**
 * Application Shell
 *
 * Add your application-wide methods in the class below, your shells
 * will inherit them.
 *
 * @package       app.Console.Command
 */
class AppShell extends Shell
{
    public $tasks = array('ConfigLoad');

    public function initialize()
    {
        parent::initialize();
        $this->ConfigLoad = $this->Tasks->load('ConfigLoad');
        $this->ConfigLoad->execute();
    }

    public function perform()
    {
        $this->initialize();
        $this->{array_shift($this->args)}();
    }

    protected function _welcome()
    {
        // disable welcome message
    }

    /**
     * @param mixed $data
     * @return string
     * @throws JsonException
     */
    protected function json($data)
    {
        return json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    }

    /**
     * @param mixed $value
     * @return bool
     */
    protected function toBoolean($value)
    {
        $value = strtolower($value);
        switch ($value) {
            case 'true':
            case '1':
                return true;
            case 'false':
            case '0':
                return false;
            default:
                $this->error("Invalid state value `$value`, it must be `true`, `false`, `1`, or `0`.");
        }
    }
}
