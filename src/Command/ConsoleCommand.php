<?php
declare(strict_types=1);

/**
 * CakePHP(tm) : Rapid Development Framework (https://cakephp.org)
 * Copyright (c) Cake Software Foundation, Inc. (https://cakefoundation.org)
 *
 * Licensed under The MIT License
 * For full copyright and license information, please see the LICENSE.txt
 * Redistributions of files must retain the above copyright notice.
 *
 * @copyright Copyright (c) Cake Software Foundation, Inc. (https://cakefoundation.org)
 * @link      https://cakephp.org CakePHP(tm) Project
 * @since     3.0.0
 * @license   https://opensource.org/licenses/mit-license.php MIT License
 */
namespace App\Command;

use Cake\Console\Arguments;
use Cake\Console\Command;
use Cake\Console\ConsoleIo;
use Cake\Console\ConsoleOptionParser;
use Cake\Log\Log;
use Psy\Shell as PsyShell;

/**
 * Simple console wrapper around Psy\Shell.
 */
class ConsoleCommand extends Command
{
    /**
     * Start the Command and interactive console.
     *
     * @param \Cake\Console\Arguments $args The command arguments.
     * @param \Cake\Console\ConsoleIo $io The console io
     * @return int|null|void The exit code or null for success
     */
    public function execute(Arguments $args, ConsoleIo $io)
    {
        if (!class_exists('Psy\Shell')) {
            $io->err('<error>Unable to load Psy\Shell.</error>');
            $io->err('');
            $io->err('Make sure you have installed psysh as a dependency,');
            $io->err('and that Psy\Shell is registered in your autoloader.');
            $io->err('');
            $io->err('If you are using composer run');
            $io->err('');
            $io->err('<info>$ php composer.phar require --dev psy/psysh</info>');
            $io->err('');

            return static::CODE_ERROR;
        }

        $io->out("You can exit with <info>`CTRL-C`</info> or <info>`exit`</info>");
        $io->out('');

        Log::drop('debug');
        Log::drop('error');
        $io->setLoggers(false);
        restore_error_handler();
        restore_exception_handler();

        $psy = new PsyShell();
        $psy->run();
    }

    /**
     * Display help for this console.
     *
     * @param \Cake\Console\ConsoleOptionParser $parser The parser to update
     * @return \Cake\Console\ConsoleOptionParser
     */
    public function buildOptionParser(ConsoleOptionParser $parser): ConsoleOptionParser
    {
        $parser->setDescription(
            'This shell provides a REPL that you can use to interact with ' .
            'your application in a command line designed to run PHP code. ' .
            'You can use it to run adhoc queries with your models, or ' .
            'explore the features of CakePHP and your application.' .
            "\n\n" .
            'You will need to have psysh installed for this Shell to work.'
        );

        return $parser;
    }
}
