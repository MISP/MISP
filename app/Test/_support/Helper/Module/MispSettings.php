<?php

namespace Helper\Module;

use Exception;

final class MispSettings extends \Codeception\Module implements \Codeception\Lib\Interfaces\DependsOnModule
{

    /** @var array */
    protected $config = [
        'docker' => false,
    ];

    private $cliModule;

    public function _depends()
    {
        return ['Codeception\Module\Cli' => 'Cli is a mandatory dependency of MispSettings'];
    }

    public function _inject(\Codeception\Module\Cli $cliModule)
    {
        $this->cliModule = $cliModule;
    }

    public function haveMispSetting($setting, $value)
    {
        if (isset($this->config['docker'])) {
            if (!isset($this->config['docker_compose_file'])) {
                throw new Exception('Config key `docker_compose_file` must be set when running in docker mode.');
            } else {
                $cmd = sprintf(
                    'docker-compose -f %s exec misp bash -c "app/Console/cake Admin setSetting %s %s"',
                    $this->config['docker_compose_file'],
                    $setting,
                    $value
                );
            }
        } else {
            // TODO: Support setting configs on local installations
            $cmd = sprintf(
                "app/Console/cake Admin setSetting %s %s",
                $this->config['docker_compose_file'],
                $setting,
                $value
            );
            throw new Exception('Running on local installation not supported, only docker available.');
        }

        try {
            $this->cliModule->runShellCommand($cmd);
        } catch (Exception $ex) {
            throw new Exception('Failed to set MISP setting', 0, $ex);
        }
    }
}
