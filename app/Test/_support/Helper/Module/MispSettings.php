<?php

declare(strict_types=1);

namespace Helper\Module;

use Exception;
use \Codeception\Module\Cli;

final class MispSettings extends \Codeception\Module implements \Codeception\Lib\Interfaces\DependsOnModule
{

    /** @var array<mixed> */
    protected $config = [
        'docker' => false,
    ];

    /** @var Cli */
    private $cliModule;

    public function _depends()
    {
        return ['Codeception\Module\Cli' => 'Cli is a mandatory dependency of MispSettings'];
    }

    public function _inject(Cli $cliModule): void
    {
        $this->cliModule = $cliModule;
    }

    public function haveMispSetting(string $setting, string $value): void
    {
        if (isset($this->config['docker'])) {
            if (!isset($this->config['docker_compose_file'])) {
                throw new Exception('Config key `docker_compose_file` must be set when running in docker mode.');
            } else {
                $cmd = sprintf(
                    'docker-compose -f %s exec -T --user www-data misp bash -c "/var/www/MISP/app/Console/cake Admin setSetting %s %s"',
                    $this->config['docker_compose_file'],
                    $setting,
                    $value
                );
            }
        } else {
            // TODO: Support setting configs on local installations
            $cmd = sprintf(
                "app/Console/cake Admin setSetting %s %s",
                $setting,
                $value
            );
            throw new Exception('Running on local installation not supported, only docker available.');
        }

        try {
            $this->cliModule->runShellCommand($cmd);
            sleep(2); // otherwise sometimes the config change does not reflect
        } catch (Exception $ex) {
            throw new Exception(
                sprintf('Failed to set MISP setting: %s', $this->cliModule->grabShellOutput()),
                0,
                $ex
            );
        }
    }
}
