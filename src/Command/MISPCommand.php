<?php

namespace App\Command;

use App\Lib\Tools\BackgroundJobsTool;
use Cake\Command\Command;
use Cake\Console\Arguments;
use Cake\Console\ConsoleIo;
use Cake\Core\Configure;

class MISPCommand extends Command
{
    /** @var ConsoleIo */
    protected $io;

    /** @var array */
    protected $arguments = [];

    /** @var string */
    protected $action = '';

    /** @var array */
    protected $validActions = [];

    /** @var array */
    protected $usage = [];

    /** @var BackgroundJobsTool */
    private static $loadedBackgroundJobsTool;

    public function execute(Arguments $args, ConsoleIo $io)
    {
        $this->io = $io;

        $this->arguments = $args->getArguments();
        $this->action = array_shift($this->arguments);

        if (empty($this->action)) {
            $this->showActionUsageAndExit();
        }

        if (!in_array($this->action, $this->validActions)) {
            $this->invalidAction();
        }

        call_user_func([$this, $this->action], ...$this->arguments);

        parent::execute($args, $io);
    }

    protected function outputJson($data)
    {
        $this->io->out(json_encode($data, JSON_PRETTY_PRINT));
    }

    protected function showActionUsageAndExit()
    {
        $this->io->error('Invalid usage.');
        if (!empty($this->usage) && isset($this->usage[$this->action])) {
            $this->io->info('Usage: ' . $this->usage[$this->action]);
        }
        die();
    }

    protected function invalidAction()
    {
        $this->io->warning('Invalid action.');
        $this->io->out('Valid actions: ' . implode(', ', $this->validActions));
        die();
    }

    /**
     * @return BackgroundJobsTool
     */
    public function getBackgroundJobsTool(): BackgroundJobsTool
    {
        if (!self::$loadedBackgroundJobsTool) {
            self::$loadedBackgroundJobsTool = new BackgroundJobsTool(Configure::read('BackgroundJobs'));
            ;
        }

        return self::$loadedBackgroundJobsTool;
    }

    /**
     * @param int $userId
     * @return array
     */
    protected function getUser($userId): array
    {
        $UsersTable = $this->fetchTable('Users');
        $user = $UsersTable->getAuthUser($userId, true);

        if (empty($user)) {
            $this->io->error('User ID do not match an existing user.');
            die();
        }

        return $user->toArray();
    }
}
