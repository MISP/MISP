<?php
namespace App\Command;

use Cake\Console\Arguments;
use Cake\Console\Command;
use Cake\Console\ConsoleIo;
use Cake\Utility\Security;

class UserCommand extends Command
{
    protected $modelClass = 'Users';

    public function execute(Arguments $args, ConsoleIo $io)
    {
        $exit = false;
        while (!$exit) {
            $menu = [
                ['', 'MISP users'],
                ['1', 'List users'],
                ['2', 'Reset password for a user'],
                ['3', 'Enable/Disable a user'],
                ['4', 'Reset admin'],
                ['0', 'Exit']
            ];
            $io->helper('Table')->output($menu);
            $choice = $io->ask('What would you like to do?');
            switch ($choice) {
                case '1':
                    $io->helper('Table')->output($this->listUsers());
                    break;
                case '2':
                    $user = $io->ask('Which user do you want to reset?');
                    $user = $this->selectUser($user);
                    if (empty($user)) {
                        $io->out('Invalid user.');
                    } else {
                        $automatic = $io->ask(sprintf('Would you like to generate a password automatically for user "%s"? (y/n)', $user['username']));
                        if ($automatic === 'y') {
                            $password = $this->generatePassword();
                        } elseif ($automatic === 'n') {
                            $password = $io->ask('Please enter the desired password:');
                        }
                        if (!empty($password)) {
                            if ($this->setPassword($user, $password)) {
                                $io->out(sprintf('Password reset for user "%s". The new password is: "%s"', $user['username'], $password));
                            } else {
                                $io->out('Could not save the provided password. Are you sure it meets the requirements?');
                            }
                        } else {
                            $io->out('Password empty, change aborted.');
                        }
                    }
                    break;
                case '3':
                    $user = $io->ask(__('Which user do you want to enable/disable?'));
                    $user = $this->selectUser($user);
                    if (empty($user)) {
                        $io->out('Invalid user.');
                    } else {
                        $confirm = $io->askChoice(__('Do you want to {0} the user {1}', $user->disabled ? __('enable') : __('disable'), $user->username), ['Y', 'N'], 'N');
                        if ($confirm) {
                            $user = $this->toggleDisable($user);
                            if ($user) {
                                $io->out(__('User {0}', !$user->disabled ? __('enabled') : __('disabled')));
                            } else {
                                $io->out('Could not save the disabled flag.');
                            }
                        }
                    }
                    break;
                case '4':
                    $this->resetAdmin();
                    break;
                case '0':
                    $exit = true;
                    break;
                default:
                    $io->out('Invalid selection');
                    break;
            }
        }
        $io->out('Goodbye!');
    }

    private function generatePassword()
    {
        return Security::randomString(16);
    }

    private function listUsers()
    {
        $users = $this->Users->find()->contain(['Individuals'])->all();
        $list = [['ID', 'Username', 'Email']];
        foreach ($users as $user) {
            $list[] = [
                (string)$user['id'], $user['username'], $user['individual']['email']
            ];
        }
        return $list;
    }

    private function selectUser($user)
    {
        if (is_numeric($user)) {
            $condition = ['id' => $user];
        } else {
            $condition = ['username' => $user];
        }
        $user = $this->Users->find()->where($condition)->first();
        return $user;
    }

    private function setPassword($user, $password)
    {
        $user->password = $password;
        return $this->Users->save($user);
    }

    private function resetAdmin()
    {
	$user = $this->Users->find()->where(['email' => 'admin@admin.test'])->first();
	$user->password = 'Password1234';
	return $this->Users->save($user);
    }

    private function toggleDisable($user)
    {
        $user->disabled = !$user->disabled;
        return $this->Users->save($user);
    }
}
