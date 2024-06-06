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
App::uses('BackgroundJobsTool', 'Tools');
App::uses('BenchmarkTool', 'Tools');

require_once dirname(__DIR__) . '/../Model/Attribute.php';   // FIXME workaround bug where Vendor/symfony/polyfill-php80/Resources/stubs/Attribute.php is loaded instead

/**
 * Application Shell
 *
 * Add your application-wide methods in the class below, your shells
 * will inherit them.
 *
 * @package       app.Console.Command
 */
abstract class AppShell extends Shell
{
    /** @var BackgroundJobsTool */
    private $BackgroundJobsTool;

    public function initialize()
    {
        $configLoad = $this->Tasks->load('ConfigLoad');
        $configLoad->execute();
        if (Configure::read('Plugin.Benchmarking_enable')) {
            $Benchmark = new BenchmarkTool(ClassRegistry::init('User'));
            $start_time = $Benchmark->startBenchmark();
            register_shutdown_function(function () use ($start_time, $Benchmark) {
                $Benchmark->stopBenchmark([
                    'user' => 0,
                    'controller' => 'Shell::' . $this->modelClass,
                    'action' => $this->command,
                    'start_time' => $start_time
                ]);
            });
        }
        parent::initialize();
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
        return JsonTool::encode($data, true);
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

    /**
     * @param string $newCommand
     * @return void
     */
    protected function deprecated($newCommand)
    {
        $this->err("<warning>Warning: This method is deprecated. Next time please use `$newCommand`.</warning>");
    }

    /**
     * @return BackgroundJobsTool
     * @throws Exception
     */
    protected function getBackgroundJobsTool()
    {
        if (!isset($this->BackgroundJobsTool)) {
            $settings = ['enabled' => false];
            if (!empty(Configure::read('SimpleBackgroundJobs.enabled'))) {
                $settings = Configure::read('SimpleBackgroundJobs');
            }
            $this->BackgroundJobsTool = new BackgroundJobsTool($settings);
        }
        return $this->BackgroundJobsTool;
    }
}
