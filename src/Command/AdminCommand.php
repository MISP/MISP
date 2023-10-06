<?php

namespace App\Command;

use Cake\Console\Arguments;
use Cake\Console\Command;
use Cake\Console\ConsoleIo;
use Cake\ORM\Locator\LocatorAwareTrait;
use App\Model\Entity\Server;

class AdminCommand extends Command
{
    use LocatorAwareTrait;

    /** @var ConsoleIo */
    private $io;

    public function execute(Arguments $args, ConsoleIo $io)
    {
        $this->io = $io;

        $arguments = $args->getArguments();
        $action = array_shift($arguments);

        switch ($action) {
            case 'prune_update_logs':
                $this->pruneUpdateLogs(...$arguments);
                break;
            default:
                $this->io->err('Invalid action.');
        }
        $this->io->out("Bye.");
    }

    private function pruneUpdateLogs($jobId, $userId)
    {
        $this->io->out('Pruning update logs...');

        $this->io->out(print_r($_ENV, true));

        if (empty($jobId) || empty($userId)) {
            die('Usage: ' . (new Server())->command_line_functions['console_admin_tasks']['data']['Prune update logs'] . PHP_EOL);
        }

        $UsersTable = $this->fetchTable('Users');

        $user = $UsersTable->getAuthUser($userId)->toArray();

        $JobsTable = $this->fetchTable('Jobs');
        $LogsTable = $this->fetchTable('Logs');

        $jobEntity = $JobsTable->get($jobId);
        $LogsTable->pruneUpdateLogs($user, $jobId);

        $jobEntity->progress = 100;
        $jobEntity->message = 'Job done.';
        $jobEntity->status = 4;

        $this->io->out('Done.');
    }

    private function updateNoticeLists()
    {
        $this->io->out('Updating Noticelists...');

        $NoticelistTable = $this->fetchTable('Noticelists');
        $result = $NoticelistTable->update();

        if ($result) {
            $this->io->info('Noticelists updated');
        } else {
            $this->io->err('Could not update notice lists');
        }

        $this->io->out('Done.');
    }
}
