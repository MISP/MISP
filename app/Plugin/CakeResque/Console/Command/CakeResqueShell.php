<?php
/**
 * CakeResque Shell File
 *
 * Use to manage the workers via CLI
 *
 * PHP version 5
 *
 * Licensed under The MIT License
 * Redistributions of files must retain the above copyright notice.
 *
 * @author        Wan Qi Chen <kami@kamisama.me>
 * @copyright     Copyright 2012, Wan Qi Chen <kami@kamisama.me>
 * @link          http://cakeresque.kamisama.me
 * @package       CakeResque
 * @subpackage	  CakeResque.Console.Command
 * @since         0.5
 * @license       MIT License (http://www.opensource.org/licenses/mit-license.php)
 */


class CakeResqueShell extends Shell {

	public $uses = array();

/**
 * Absolute path to the php-resque library.
 *
 * @var string
 */
	protected $_resqueLibrary = null;

/**
 * Runtime arguments (from command line).
 *
 * @var array
 */
	protected $_runtime = array();

/**
 * CakeResque class, proxying the Resque library.
 *
 * Actually needed for testing purposes.
 *
 * @var string
 */
	public static $cakeResque = 'CakeResque';

/**
 * Pause time before rechecking if a worker is started in microseconds.
 *
 * Actually needed for testing purposes.
 *
 * @var integer
 */
	public static $checkStartedWorkerBufferTime = 100000;

/**
 * Plugin version.
 */
	const VERSION = '4.1.2';

/**
 * Startup callback.
 *
 * Initializes defaults.
 *
 * @return void
 */
	public function startup() {
		$reflector = new ReflectionClass('Resque');
		$this->_resqueLibrary = dirname(dirname($reflector->getFileName()));

		$reflector = new ReflectionClass('ResqueScheduler\ResqueScheduler');
		$this->_resqueSchedulerLibrary = dirname(dirname(dirname($reflector->getFileName())));

		$this->ResqueStatus = new ResqueStatus\ResqueStatus(Resque::redis());

		$this->stdout->styles('success', array('text' => 'green'));
		$this->stdout->styles('bold', array('bold' => true));
	}

/**
 * Get the option parser instance and configures it.
 *
 * @return ConsoleOptionParser
 * @see Shell::getOptionParser()
 */
	public function getOptionParser() {
		$startParserArguments = array(
			'options' => array(
				'user' => array(
					'short' => 'u',
					'help' => __d('cake_resque', 'User running the workers')
				),
				'queue' => array(
					'short' => 'q',
					'help' => __d('cake_resque', 'Name of the queue. If multiple queues, separe with comma.')
				),
				'interval' => array(
					'short' => 'i',
					'help' => __d('cake_resque', 'Pause time in seconds between each works')
				),
				'workers' => array(
					'short' => 'n',
					'help' => __d('cake_resque', 'Number of workers to fork')
				),
				'log' => array(
					'short' => 'l',
					'help' => __d('cake_resque', 'Log path')
				),
				'log-handler' => array(
					'help' => __d('cake_resque', 'Log Handler to use for logging.')
				),
				'log-handler-target' => array(
					'help' => __d('cake_resque', 'Log Handler arguments')
				),
				'verbose' => array(
					'short' => 'v',
					'help' => __d('cake_resque', 'Log more verbose informations'),
					'boolean' => true
				),
				'debug' => array(
					'short' => 'd',
					'help' => __d('cake_resque', 'Print debug informations'),
					'boolean' => true
				)
			)
		);

		$startSchedulerParserArguments = array(
			'options' => array(
				'user' => array(
					'short' => 'u',
					'help' => __d('cake_resque', 'User running the workers')
				),
				'interval' => array(
					'short' => 'i',
					'help' => __d('cake_resque', 'Pause time in seconds between each works')
				),
				'log' => array(
					'short' => 'l',
					'help' => __d('cake_resque', 'Log path')
				),
				'log-handler' => array(
					'help' => __d('cake_resque', 'Log Handler to use for logging.')
				),
				'log-handler-target' => array(
					'help' => __d('cake_resque', 'Log Handler arguments')
				),
				'verbose' => array(
					'short' => 'v',
					'help' => __d('cake_resque', 'Log more verbose informations'),
					'boolean' => true
				)
			)
		);

		$stopParserArguments = array(
			'options' => array(
				'force' => array(
					'short' => 'f',
					'help' => __d('cake_resque', 'Force workers shutdown, forcing all the current jobs to finish (and fail)'),
					'boolean' => true
				),
				'all' => array(
					'short' => 'a',
					'help' => __d('cake_resque', 'Shutdown all workers'),
					'boolean' => true
				)
			),
			'description' => array(
				__d('cake_resque', 'Stop one or all workers'),
				__d('cake_resque', 'Unless you force the stop with the --force option,'),
				__d('cake_resque', 'the worker will wait for all jobs to complete'),
				__d('cake_resque', 'before shutting down')
			)
		);

		$pauseParserArguments = array(
			'options' => array(
				'all' => array(
					'short' => 'a',
					'help' => __d('cake_resque', 'Pause all workers'),
					'boolean' => true
				),
				'debug' => array(
					'short' => 'd',
					'help' => __d('cake_resque', 'Print debug informations'),
					'boolean' => true
				)
			),
			'description' => array(
				__d('cake_resque', 'Pause one or all workers'),
				__d('cake_resque', 'Pausing is only supported on Unix system,'),
				__d('cake_resque', 'with PHP pcntl extension installed')
			)
		);

		$resumeParserArguments = array(
			'options' => array(
				'all' => array(
					'short' => 'a',
					'help' => __d('cake_resque', 'Resume all paused workers'),
					'boolean' => true
				),
				'debug' => array(
					'short' => 'd',
					'help' => __d('cake_resque', 'Print debug informations'),
					'boolean' => true
				)
			),
			'description' => array(
				__d('cake_resque', 'Resume one or all paused workers'),
				__d('cake_resque', 'Resuming is only supported on Unix system,'),
				__d('cake_resque', 'with PHP pcntl extension installed')
			)
		);

		$cleanupParserArguments = array(
			'options' => array(
				'all' => array(
					'short' => 'a',
					'help' => __d('cake_resque', 'Clean up all workers'),
					'boolean' => true
				),
				'debug' => array(
					'short' => 'd',
					'help' => __d('cake_resque', 'Print debug informations'),
					'boolean' => true
				)
			),
			'description' => array(
				__d('cake_resque', 'Cleaning Up one or all paused workers'),
				__d('cake_resque', 'Cleaning Up will immedately terminate the job'),
				__d('cake_resque', 'the worker is currently working on.'),
				__d('cake_resque', 'Resuming is only supported on Unix system,'),
				__d('cake_resque', 'with PHP pcntl extension installed')
			)
		);

		$clearParserArguments = array(
			'options' => array(
				'all' => array(
					'short' => 'a',
					'help' => __d('cake_resque', 'Clear all queues'),
					'boolean' => true
				),
				'debug' => array(
					'short' => 'd',
					'help' => __d('cake_resque', 'Print debug informations'),
					'boolean' => true
				)
			),
			'description' => array(
				__d('cake_resque', 'Clear one or all queues'),
				__d('cake_resque', 'Clearing a queue will remove all its jobs')
			)
		);

		return parent::getOptionParser()
			->description(
				__d('cake_resque', "A Shell to manage PHP Resque") . "\n" .
				__d('cake_resque', "Version " . CakeResqueShell::VERSION) . "\n" .
				"Wan Chen (" . date('Y') . ")"
				)
			->addSubcommand('start', array(
				'help' => __d('cake_resque', 'Start a new worker.'),
				'parser' => $startParserArguments
			))
			->addSubcommand('startscheduler', array(
				'help' => __d('cake_resque', 'Start a new scheduler worker.'),
				'parser' => $startSchedulerParserArguments
			))
			->addSubcommand('stop', array(
				'help' => __d('cake_resque', 'Stop a worker.'),
				'parser' => $stopParserArguments
			))
			->addSubcommand('pause', array(
				'help' => __d('cake_resque', 'Pause a worker.'),
				'parser' => $pauseParserArguments
			))
			->addSubcommand('resume', array(
				'help' => __d('cake_resque', 'Resume a paused worker.'),
				'parser' => $resumeParserArguments
			))
			->addSubcommand('cleanup', array(
				'help' => __d('cake_resque', 'Immediately terminate a worker job execution.'),
				'parser' => $cleanupParserArguments
			))
			->addSubcommand('restart', array(
				'help' => __d('cake_resque', 'Stop all Resque workers, and start a new one.'),
				'parser' => array_merge_recursive($startParserArguments, $stopParserArguments)
			))
			->addSubcommand('clear', array(
				'help' => __d('cake_resque', 'Clear all jobs inside a queue'),
				'parser' => $clearParserArguments
			))
			->addSubcommand('reset', array(
				'help' => __d('cake_resque', 'Reset CakeResque internal worker\'s saved status'),
				'parser' => $clearParserArguments
			))
			->addSubcommand('stats', array(
				'help' => __d('cake_resque', 'View stats about processed/failed jobs.')
			))
			->addSubcommand('tail', array(
				'help' => __d('cake_resque', 'Tail the workers logs.')
			))
			->addSubcommand('track', array(
				'help' => __d('cake_resque', 'Track a job status.')
			))
			->addSubcommand('load', array(
				'help' => __d('cake_resque', 'Load a set of predefined workers.')
		));
	}

/**
 * Enqueue a job via CLI.
 *
 * @return bool False if enqueueing fails.
 */
	public function enqueue() {
		$this->out('<info>' . __d('cake_resque', 'Adding a job to worker') . '</info>');
		if (count($this->args) !== 3) {
			$this->err('<error>' . __d('cake_resque', 'Wrong number of arguments') . '</error>');
			$this->out(__d('cake_resque', 'Usage : enqueue <queue> <jobclass> <comma-separated-args>'), 2);
			return false;
		}

		$result = call_user_func_array(
			CakeResqueShell::$cakeResque . '::enqueue',
			array($this->args[0], $this->args[1], explode(',', $this->args[2]))
		);
		$this->out('<success>' . __d('cake_resque', 'Succesfully enqueued Job #%s', $result) . '</success>');

		$this->out('');
	}

/**
 * Enqueue a scheduled job via CLI.
 *
 * @since 2.3.0
 * @return bool False if enqueueing fails.
 */
	public function enqueueIn() {
		$this->out('<info>' . __d('cake_resque', 'Scheduling a job') . '</info>');
		if (count($this->args) !== 4) {
			$this->err('<error>' . __d('cake_resque', 'Wrong number of arguments') . '</error>');
			$this->out(__d('cake_resque', 'Usage : enqueueIn <seconds> <queue> <jobclass> <comma-separated-args>'), 2);
			return false;
		}

		$result = call_user_func_array(
			CakeResqueShell::$cakeResque . '::enqueueIn',
			array($this->args[0], $this->args[1], $this->args[2], explode(',', $this->args[3]), (isset($this->args[4]) ? (bool)$this->args[4] : false))
		);

		$this->out('<success>' . __d('cake_resque', 'Succesfully scheduled Job #%s', $result) . '</success>');

		$this->out('');
	}

/**
 * Enqueue a scheduled job via CLI.
 *
 * @since 2.3.0
 * @return bool False if enqueueing fails.
 */
	public function enqueueAt() {
		$this->out('<info>' . __d('cake_resque', 'Scheduling a job') . '</info>');
		if (count($this->args) !== 4) {
			$this->err('<error>' . __d('cake_resque', 'Wrong number of arguments') . '</error>');
			$this->out(__d('cake_resque', 'Usage : enqueue <timestamp> <queue> <jobclass> <comma-separated-args>'), 2);
			return false;
		}

		$result = call_user_func_array(
			CakeResqueShell::$cakeResque . '::enqueueAt',
			array($this->args[0], $this->args[1], $this->args[2], explode(',', $this->args[3]), (isset($this->args[4]) ? (bool)$this->args[4] : false))
		);
		$this->out('<success>' . __d('cake_resque', 'Succesfully scheduled Job #%s', $result) . '</success>');

		$this->out('');
	}

/**
 * Monitor the content of a log file onscreen.
 *
 * Ask user to choose from a list of available log file, if there's more than one,
 * and display all new content on screen.
 * This will only search for log file created by resque, and the RotatingFile created by log-handler.
 *
 * Note: The workers status is conveniently stored by ResqueStatus.
 *
 * @return bool False if no logs to tail.
 * @see ResqueStatus\ResqueStatus::getWorkers()
 */
	public function tail() {
		$logs = array();
		$i = 1;
		$workersArgs = $this->ResqueStatus->getWorkers();

		foreach ($workersArgs as $workerArgs) {
			if ($workerArgs['log'] != '') {
				$logs[] = $workerArgs['log'];
			}
			if ($workerArgs['Log']['handler'] == 'RotatingFile') {
				$fileInfo = pathinfo($workerArgs['Log']['target']);
				$pattern = $fileInfo['dirname'] . DS . $fileInfo['filename'] . '-*' . (!empty($fileInfo['extension']) ? '.' . $fileInfo['extension'] : '');

				$logs = array_merge($logs, glob($pattern));
			}
		}

		$logs = array_values(array_unique($logs));

		$this->out('<info>' . __d('cake_resque', 'Tailing log file') . '</info>');
		if (empty($logs)) {
			$this->out('    <error>' . __d('cake_resque', 'No log file to tail') . '</error>', 2);
			return false;
		} elseif (count($logs) == 1) {
			$index = 1;
		} else {
			foreach ($logs as $log) {
				$this->out(sprintf('    [%3d] - %s', $i++, $log));
			}

			$index = $this->in(__d('cake_resque', 'Choose a log file to tail') . ':', range(1, $i - 1));
		}

		$this->out('<warning>' . __d('cake_resque', 'Tailing %s', $logs[$index - 1]) . '</warning>');
		$this->_tail($logs[$index - 1]);
	}

/**
 * Start the scheduler worker.
 *
 * @param array $args Command line arguments used to start the worker with.
 * @since 2.3.0
 * @return bool False is starting the worker fails.
 */
	public function startScheduler($args = null) {
		return $this->start($args, true);
	}

/**
 * Create a new worker.
 *
 * Note: The workers status is conveniently stored by ResqueStatus.
 *
 * @param array $args Command line arguments used to start the worker with.
 * @param bool $scheduler Whether the worker is a scheduler worker.
 * @return bool False is starting the worker fails.
 * @see ResqueStatus\ResqueStatus::addWorker()
 * @see ResqueStatus\ResqueStatus::isRunningSchedulerWorker()
 * @see ResqueStatus\ResqueStatus::registerSchedulerWorker()
 */
	public function start($args = null, $scheduler = false) {
		if ($args === null) {
			$this->out('<info>' .
				($scheduler ?
					__d('cake_resque', 'Creating the scheduler workers') :
					__d('cake_resque', 'Creating workers')) .
				'</info>'
			);
		}

		$ResqueStatus = $this->ResqueStatus;

		if ($scheduler) {
			if (Configure::read('CakeResque.Scheduler.enabled') !== true) {
				$this->out('<error>' . __d('cake_resque', 'Scheduler Worker is not enabled') . '</error>');
				return false;
			}

			if ($ResqueStatus->isRunningSchedulerWorker()) {
				$this->out('<warning>' . __d('cake_resque', 'The scheduler worker is already running') . '</warning>');
				return false;
			}

			$args['type'] = 'scheduler';
		}

		if (!$this->_validate($args)) {
			return false;
		}

		if (file_exists(APP . 'Lib' . DS . 'CakeResqueBootstrap.php')) {
			$bootstrapPath = APP . 'Lib' . DS . 'CakeResqueBootstrap.php';
		} else {
			$bootstrapPath = App::pluginPath('CakeResque') . 'Lib' . DS . 'CakeResqueBootstrap.php';
		}

		if ($scheduler) {
			$libraryPath = $this->_resqueSchedulerLibrary;
			$logFile = Configure::read('CakeResque.Scheduler.log');
			$resqueBin = './bin/resque-scheduler.php';
			$vars = Configure::read('CakeResque.Scheduler.Env');
		} else {
			$libraryPath = $this->_resqueLibrary;
			$logFile = $this->_runtime['log'];
			$resqueBin = $this->_getResqueBinFile($this->_resqueLibrary);
			$vars = Configure::read('CakeResque.Env');
		}

		$envVars = array();
		foreach ($vars as $key => $val) {
			if (is_int($key) && isset($_SERVER[$val])) {
				$envVars[] = sprintf("%s=%s", $val, escapeshellarg($_SERVER[$val]));
			} else {
				$envVars[] = sprintf("%s=%s", $key, escapeshellarg($val));
			}
		}

		$pidFile = Configure::read('CakeResque.Resque.tmpdir') . str_replace('.', '', microtime(true));

		$cmd = implode(' ', array(
			sprintf("nohup %s \\\n", ($this->_runtime['user'] === $this->__getProcessOwner()) ? "" : "sudo -u " . $this->_runtime['user']),
			sprintf("bash -c \"cd %s; \\\n", escapeshellarg($libraryPath)),
			implode(' ', $envVars),
			" \\\n",
			sprintf("%sVERBOSE=true \\\n", $this->_runtime['verbose'] ? 'V' : ''),
			sprintf("QUEUE=%s \\\n", escapeshellarg($this->_runtime['queue'])),
			sprintf("PIDFILE=%s \\\n", escapeshellarg($pidFile)),
			sprintf("APP_INCLUDE=%s \\\n", escapeshellarg($bootstrapPath)),
			sprintf("RESQUE_PHP=%s \\\n", escapeshellarg($this->_resqueLibrary . DS . 'lib' . DS . 'Resque.php')),
			sprintf("INTERVAL=%s \\\n", $this->_runtime['interval']),
			sprintf("REDIS_BACKEND=%s \\\n", escapeshellarg(Configure::read('CakeResque.Redis.host') . ':' . Configure::read('CakeResque.Redis.port'))),
			sprintf("REDIS_DATABASE=%s \\\n", Configure::read('CakeResque.Redis.database')),
			sprintf("REDIS_NAMESPACE=%s \\\n", escapeshellarg(Configure::read('CakeResque.Redis.namespace'))),
			sprintf("REDIS_PASSWORD=%s \\\n", escapeshellarg(Configure::read('CakeResque.Redis.password'))),
			sprintf("CAKE=%s \\\n", escapeshellarg(CAKE)),
			sprintf("APP=%s \\\n", escapeshellarg(APP)),
			sprintf("COUNT=%s \\\n", 1),
			sprintf("LOGHANDLER=%s \\\n", escapeshellarg($this->_runtime['Log']['handler'])),
			sprintf("LOGHANDLERTARGET=%s \\\n", escapeshellarg($this->_runtime['Log']['target'])),
			sprintf("php %s \\\n", escapeshellarg($resqueBin)),
			sprintf(">> %s \\\n", escapeshellarg($logFile)),
			"2>&1\" >/dev/null 2>&1 &"
		));

		$count = $this->_runtime['workers'];

		$this->debug(__d('cake_resque', 'Will start ' . $count . ' workers'));

		for ($i = 1; $i <= $count; $i++) {
			$this->debug(__d('cake_resque', 'Starting worker (' . $i . ')'));
			$this->debug(__d('cake_resque', 'Running command : ' . "\n\t " . str_replace("\n", "\n\t", $cmd)));

			$this->_exec($cmd);

			$success = false;
			$attempt = 7;

			$this->out($scheduler ? __d('cake_resque', 'Starting scheduler worker ') : __d('cake_resque', 'Starting worker '), 0);

			while ($attempt-- > 0) {
				for ($j = 0; $j < 3;$j++) {
					$this->out(".", 0);
					usleep(CakeResqueShell::$checkStartedWorkerBufferTime);
				}

				if (false !== $pid = $this->_checkStartedWorker($pidFile)) {
					$success = true;
					$this->out(' <success>' . __d('cake_resque', 'Done') . '</success>');

					$this->debug(__d('cake_resque', 'Registering worker #' . $pid . ' to list of active workers'));

					$workerSettings = $this->_runtime;

					$workerSettings['workers'] = 1;
					unset($workerSettings['debug']);

					if ($scheduler) {
						$ResqueStatus->registerSchedulerWorker($pid);
					}

					$ResqueStatus->addWorker($pid, $workerSettings);

					break;
				}
			}

			if (!$success) {
				$this->out(' <error>' . __d('cake_resque', 'Fail') . '</error>');
			}
		}

		if ($args === null) {
			$this->out('');
		}
	}

/**
 * Stop workers.
 *
 * Will ask the user to choose the worker to stop, from a list of workers, if more
 * than one worker is running, or if --all is not passed.
 *
 * If the queues a worker is pooling from are empty, they are removed from the queues list.
 *
 * Note: The workers status is conveniently stored by ResqueStatus.
 *
 * @return void
 * @see CakeResqueShell::_sendSignal()
 * @see ResqueStatus\ResqueStatus::removeWorker()
 * @see ResqueStatus\ResqueStatus::setPausedWorker()
 * @see ResqueStatus\ResqueStatus::unregisterSchedulerWorker()
 */
	public function stop() {
		$ResqueStatus = $this->ResqueStatus;

		$actionMessage = function ($pid) {
			return __d('cake_resque', 'Stopping %s ... ', $pid);
		};

		$schedulerWorkerAction = function($worker) use ($ResqueStatus) {
			$ResqueStatus->unregisterSchedulerWorker();
		};

		$successCallback = function ($worker) use ($ResqueStatus) {
			list($host, $pid, $queue) = explode(':', (string)$worker);
			$ResqueStatus->setPausedWorker((string)$worker, false);
			$ResqueStatus->removeWorker($pid);

			$queues = $worker->queues(false);
			foreach ($queues as $queue) {
				$size = call_user_func_array(CakeResqueShell::$cakeResque . '::getQueueSize', array($queue));
				if ($size === 0) {
					call_user_func_array(CakeResqueShell::$cakeResque . '::removeQueue', array($queue));
				}
			}
		};

		return $this->_sendSignal(
			__d('cake_resque', 'Stopping workers') . ($this->params['force'] ? ' (' . __d('cake_resque', 'force') . ')' : ''),
			call_user_func(CakeResqueShell::$cakeResque . '::getWorkers'),
			__d('cake_resque', 'There is no workers to stop ...'),
			__d('cake_resque', 'Workers list'),
			__d('cake_resque', 'Stop all workers'),
			__d('cake_resque', 'Worker to stop'),
			__d('cake_resque', 'Stopping the Scheduler Worker ... '),
			$actionMessage,
			null,
			$successCallback,
			$this->params['force'] ? 'TERM' : 'QUIT',
			$schedulerWorkerAction
		);
	}

/**
 * Clean up workers.
 *
 * On supported system, will ask the user to choose the worker to clean up, from
 * a list of workers, if more than one worker is running, or if --all is not passed.
 *
 * Clean up will immediately terminate a worker child. Job is left unfinished.
 *
 * @since 2.0.0
 * @return void
 * @see CakeResqueShell::_sendSignal()
 */
	public function cleanup() {
		$actionMessage = function ($pid) {
			return __d('cake_resque', 'Cleaning up %s ... ', $pid);
		};

		$successCallback = function ($worker) {
		};

		return $this->_sendSignal(
			__d('cake_resque', 'Cleaning up workers'),
			call_user_func(CakeResqueShell::$cakeResque . '::getWorkers'),
			__d('cake_resque', 'There is no active workers to clean up ...'),
			__d('cake_resque', 'Active workers list'),
			__d('cake_resque', 'Clean up all workers'),
			__d('cake_resque', 'Worker to Cleanup'),
			__d('cake_resque', 'Cleaning up the Scheduler Worker ... '),
			$actionMessage,
			null,
			$successCallback,
			'USR1'
		);
	}

/**
 * Pause workers.
 *
 * On supported system, will ask the user to choose the worker to pause, from a list
 * of workers, if more than one worker is running, or if --all is not passed.
 *
 * Note: The workers status is conveniently stored by ResqueStatus.
 *
 * @since 2.0.0
 * @return void
 * @see CakeResqueShell::_sendSignal()
 * @see ResqueStatus\ResqueStatus::getPausedWorker()
 * @see ResqueStatus\ResqueStatus::setPausedWorker()
 */
	public function pause() {
		$ResqueStatus = $this->ResqueStatus;

		$actionMessage = function ($pid) {
			return __d('cake_resque', 'Pausing %s ... ', $pid);
		};

		$successCallback = function ($worker) use ($ResqueStatus) {
			$ResqueStatus->setPausedWorker((string)$worker);
		};

		// Active workers
		$this->debug(__d('cake_resque', 'Fetching list of active workers'));
		$activeWorkers = call_user_func(CakeResqueShell::$cakeResque . '::getWorkers');
		array_walk($activeWorkers, function (&$worker) {
			$worker = (string)$worker;
		});

		// Paused workers
		$pausedWorkers = $ResqueStatus->getPausedWorker();

		return $this->_sendSignal(
			__d('cake_resque', 'Pausing workers'),
			array_diff($activeWorkers, $pausedWorkers),
			__d('cake_resque', 'There is no active workers to pause ...'),
			__d('cake_resque', 'Active workers list'),
			__d('cake_resque', 'Pause all workers'),
			__d('cake_resque', 'Worker to pause'),
			__d('cake_resque', 'Pausing the Scheduler Worker ... '),
			$actionMessage,
			null,
			$successCallback,
			'USR2'
		);
	}

/**
 * Resume paused workers.
 *
 * On supported system, will ask the user to choose the worker to resume, from a list
 * of workers, if more than one worker is running, or if --all is not passed.
 *
 * Note: The workers status is conveniently stored by ResqueStatus.
 *
 * @since 2.0.0
 * @return void
 * @see CakeResqueShell::_sendSignal()
 * @see ResqueStatus\ResqueStatus::getPausedWorker()
 * @see ResqueStatus\ResqueStatus::setPausedWorker()
 */
	public function resume() {
		$ResqueStatus = $this->ResqueStatus;

		$actionMessage = function ($pid) {
			return __d('cake_resque', 'Resuming %s ... ', $pid);
		};

		$successCallback = function ($worker) use ($ResqueStatus) {
			$ResqueStatus->setPausedWorker((string)$worker, false);
		};

		return $this->_sendSignal(
			__d('cake_resque', 'Resuming workers'),
			$ResqueStatus->getPausedWorker(),
			__d('cake_resque', 'There is no paused workers to resume ...'),
			__d('cake_resque', 'Paused workers list'),
			__d('cake_resque', 'Resume all workers'),
			__d('cake_resque', 'Worker to resume'),
			__d('cake_resque', 'Resuming the Scheduler Worker ... '),
			$actionMessage,
			null,
			$successCallback,
			'CONT'
		);
	}

/**
 * Operate over workers by sending a PCNTL signal.
 *
 * Note: The workers status is conveniently stored by ResqueStatus.
 *
 * @param string $title Action title
 * @param array $workers List of workers
 * @param string $noWorkersMessage Message when there is not workers
 * @param string $listTitle Title of the list of workers
 * @param string $allActionMessage Message for executing the action on all workers
 * @param string $promptMessage Prompt message
 * @param string $schedulerWorkerActionMessage Message for executing the action on the scheduler worker
 * @param string $workerActionMessage Mesage for executing the action on a regular worker
 * @param function $formatListItem Function used to format each list item
 * @param function $successCallback Action executed on success
 * @param string $signal Signal to send to the worker process
 * @param function $schedulerWorkerAction Action to execute on the scheduled worker
 * @return void
 * @see ResqueStatus\ResqueStatus::isSchedulerWorker()
 */
	protected function _sendSignal($title, $workers, $noWorkersMessage, $listTitle,
		$allActionMessage, $promptMessage, $schedulerWorkerActionMessage,
		$workerActionMessage, $formatListItem, $successCallback, $signal, $schedulerWorkerAction = null) {
		if (!function_exists('pcntl_signal')) {
			return $this->out('<error>' .
				__d('cake_resque', "This function requires the PCNTL extension") . '</error>');
		}

		$ResqueStatus = $this->ResqueStatus;

		if ($formatListItem === null) {
			$formatListItem = function ($worker, $i) use ($ResqueStatus) {
				App::uses('CakeTime', 'Utility');
				return sprintf("    [%3d] - %s, started %s", $i, $ResqueStatus->isSchedulerWorker($worker) ? '<comment>**Scheduler Worker**</comment>' : $worker,
					CakeTime::timeAgoInWords(call_user_func(CakeResqueShell::$cakeResque . '::getWorkerStartDate', $worker)));
			};
		}

		$this->out('<info>' . $title . '</info>');

		if (empty($workers)) {
			$this->out('   ' . $noWorkersMessage);
		} else {
			$workerIndex = array();

			if (!$this->params['all'] && count($workers) > 1) {
				$this->out($listTitle . ':');
				$i = 1;
				foreach ($workers as $worker) {
					$this->out($formatListItem($worker, $i++));
				}

				$options = range(1, $i - 1);

				if ($i > 2) {
					$this->out('    [all] - ' . $allActionMessage);
					$options[] = 'all';
				}

				$in = $this->in($promptMessage . ': ', $options);
				if ($in == 'all') {
					$workerIndex = range(1, count($workers));
				} else {
					$workerIndex[] = $in;
				}
			} else {
				$workerIndex = range(1, count($workers));
			}

			foreach ($workerIndex as $index) {
				$worker = $workers[$index - 1];

				list($hostname, $pid, $queue) = explode(':', (string)$worker);
				if (Configure::read('CakeResque.Scheduler.enabled') === true && $ResqueStatus->isSchedulerWorker($worker)) {
					if ($schedulerWorkerAction !== null) {
						$schedulerWorkerAction($worker);
					}
					$this->out($schedulerWorkerActionMessage, 0);
				} else {
					$this->out($workerActionMessage($pid), 0);
				}

				$killResponse = $this->_kill($signal, $pid);
				$successCallback($worker);

				if ($killResponse['code'] === 0) {
					$this->out('<success>' . __d('cake_resque', 'Done') . '</success>');

				} else {
					$this->out('<error>' . $killResponse['message'] . '</error>');
				}
			}
		}

		$this->out('');
	}

/**
 * Start a list of predefined workers.
 *
 * Note: Each predefined queue will create a new worker.
 *
 * @return void
 * @see 'CakeResque.Queues' in Config/config.php
 */
	public function load() {
		$this->out('<info>' . __d('cake_resque', 'Loading predefined workers') . '</info>');

		$debug = isset($this->params['debug']) ? $this->params['debug'] : false;
		$queues = Configure::read('CakeResque.Queues');

		if ($queues === null) {
			$this->out('   ' . __d('cake_resque', 'You have no configured workers to load.'));
		} else {
			foreach ($queues as $workerArgs) {
				$workerArgs['debug'] = $debug;
				$this->start($workerArgs);
			}
		}

		if (Configure::read('CakeResque.Scheduler.enabled') === true) {
			$this->startscheduler(array('debug' => $debug));
		}

		$this->out('');
	}

/**
 * Restart all workers.
 *
 * Note: The workers status is conveniently stored by ResqueStatus.
 *
 * @return void
 * @see ResqueStatus\ResqueStatus::getWorkers()
 */
	public function restart() {
		$workersArgs = $this->ResqueStatus->getWorkers();

		$this->params['all'] = true;
		$this->stop();

		$this->out('<info>' . __d('cake_resque', 'Restarting workers') . '</info>');
		if (!empty($workersArgs)) {
			$debug = $this->params['debug'];
			$this->debug(__d('cake_resque', 'Found ' . count($workersArgs) . ' workers to restart'));

			foreach ($workersArgs as $workerArgs) {
				$workerArgs['debug'] = $debug;
				if (isset($workerArgs['type']) && $workerArgs['type'] === 'scheduler') {
					$this->startScheduler($workerArgs);
				} else {
					$this->start($workerArgs);
				}
			}
			$this->out('');
		} else {
			$this->out('<warning>' . __d('cake_resque', 'No active workers found, will start brand new worker') . '</warning>');
			$this->start();
		}
	}

/**
 * Display usefull stats about the workers.
 *
 * Note: The workers status is conveniently stored by ResqueStatus.
 *
 * @return void
 * @see ResqueStatus\ResqueStatus::isSchedulerWorker()
 * @see ResqueStatus\ResqueStatus::getPausedWorker()
 */
	public function stats() {
		$ResqueStatus = $this->ResqueStatus;

		$workers = call_user_func(CakeResqueShell::$cakeResque . '::getWorkers');

		// List of all queues
		$queues = array_unique(call_user_func(CakeResqueShell::$cakeResque . '::getQueues'));

		// List of queues monitored by a worker
		$activeQueues = array();
		foreach ($workers as $worker) {
			$workerParams = explode(':', $worker);
			$activeQueues = array_merge($activeQueues, explode(',', array_pop($workerParams)));
		}

		$this->out("\n");
		$this->out('<info>' . __d('cake_resque', 'Resque Statistics') . '</info>');
		$this->hr();
		$this->out("\n");

		$this->out('<info>' . __d('cake_resque', 'Jobs Stats') . '</info>');
		$this->out('   ' . __d('cake_resque', 'Processed Jobs : %12s', number_format(Resque_Stat::get('processed'))));
		$this->out('   <warning>' . __d('cake_resque', 'Failed Jobs    : %12s', number_format(Resque_Stat::get('failed'))) . '</warning>');

		if (Configure::read('CakeResque.Scheduler.enabled') === true) {
			$this->out('   ' . __d('cake_resque', 'Scheduled Jobs : %12s', number_format(ResqueScheduler\Stat::get())));
		}

		$this->out("\n");

		$count = array();
		$this->out('<info>' . __d('cake_resque', 'Queues Stats') . '</info>');
		for ($i = count($queues) - 1; $i >= 0; --$i) {
			$count[$queues[$i]] = call_user_func_array(CakeResqueShell::$cakeResque . '::getQueueSize', array($queues[$i]));
			if (!in_array($queues[$i], $activeQueues) && $count[$queues[$i]] == 0) {
				unset($queues[$i]);
			}
		}

		$this->out('   ' . __d('cake_resque', 'Queues count : %d', count($queues)));
		foreach ($queues as $queue) {
			$this->out(sprintf("\t- %-15s : %12s %s", $queue, number_format($count[$queue]), __dn('cake_resque', 'pending job', 'pending jobs', $count[$queue]) . (!in_array($queue, $activeQueues) ? " <error>(unmonitored queue)</error>" : '')));
		}

		$this->out("\n");
		$this->out('<info>' . __d('cake_resque', 'Workers Stats') . '</info>');
		$this->out('   ' . __d('cake_resque', 'Workers count : %s', count($workers)));

		$pausedWorkers = $ResqueStatus->getPausedWorker();
		$schedulerWorkers = array();

		if (!empty($workers)) {
			$this->out("\t<info>" . strtoupper(__d('cake_resque', 'regular workers')) . "</info>");
			foreach ($workers as $worker) {
				if (Configure::read('CakeResque.Scheduler.enabled') === true && $ResqueStatus->isSchedulerWorker($worker)) {
					$schedulerWorkers[] = $worker;
					continue;
				}
				$this->out("\t* <bold>" . (string)$worker . '</bold>' . (in_array((string)$worker, $pausedWorkers) ? ' <warning>(' . __d('cake_resque', 'paused') . ')</warning>' : ''));
				$this->out("\t   - " . __d('cake_resque', 'Started on') . "     : " . call_user_func(CakeResqueShell::$cakeResque . '::getWorkerStartDate', $worker));
				$this->out("\t   - " . __d('cake_resque', 'Processed Jobs') . " : " . $worker->getStat('processed'));
				$worker->getStat('failed') == 0
					? $this->out("\t   - " . __d('cake_resque', 'Failed Jobs') . "    : " . $worker->getStat('failed'))
					: $this->out("\t   - <warning>" . __d('cake_resque', 'Failed Jobs') . "    : " . $worker->getStat('failed') . "</warning>");
			}
		}

		$this->out("\n");

		if (!empty($schedulerWorkers)) {
			$this->out("\t<info>" . strtoupper(__d('cake_resque', 'scheduler worker')) . "</info>" . (in_array((string)$schedulerWorkers[0], $pausedWorkers) ? ' <warning>(' . __d('cake_resque', 'paused') . ')</warning>' : ''));
			foreach ($schedulerWorkers as $worker) {
				$schedulerWorker = new ResqueScheduler\ResqueScheduler();
				$delayedJobCount = $schedulerWorker->getDelayedQueueScheduleSize();
				$this->out("\t   - " . __d('cake_resque', 'Started on') . "     : " . call_user_func(CakeResqueShell::$cakeResque . '::getWorkerStartDate', $worker));
				$this->out("\t   - " . __d('cake_resque', 'Delayed Jobs') . "   : " . $delayedJobCount);

				if ($delayedJobCount > 0) {
					$this->out("\t   - " . __d('cake_resque', 'Next Job on') . "    : " . strftime('%a %b %d %H:%M:%S %Z %Y', $schedulerWorker->nextDelayedTimestamp()));
				}
			}
			$this->out("\n");
		} elseif (Configure::read('CakeResque.Scheduler.enabled') === true) {
			$jobsCount = ResqueScheduler\ResqueScheduler::getDelayedQueueScheduleSize();
			if ($jobsCount > 0) {
				$this->out("\t<error>************ " . __d('cake_resque', 'Alert') . " ************</error>");
				$this->out("\t<bold>" . __d('cake_resque', 'The Scheduler Worker is not running') . "</bold>");
				$this->out("\t" . __d('cake_resque', 'But there is still <bold>%d</bold> scheduled jobs left in its queue', $jobsCount));
				$this->out("\t<error>********************************</error>");
				$this->out("\n");
			}
		}
	}

/**
 * Track a job status.
 *
 * @since 2.1.0
 * @return void
 * @return bool False is tracking the job status fails.
 */
	public function track() {
		$this->out('<info>' . __d('cake_resque', 'Tracking job status') . '</info>');

		if (isset($this->args[0])) {
			$jobId = $this->args[0];
		} else {
			$this->out('<error>' . __d('cake_resque', 'Please provide a valid job ID') . "</error>\n");
			return false;
		}

		$jobStatus = call_user_func(CakeResqueShell::$cakeResque . '::getJobStatus', $jobId);

		if ($jobStatus === false) {
			$this->out(__d('cake_resque', 'Status') . ' : <warning>' . __d('cake_resque', 'Unknown') . '</warning>');
		} else {
			$statusName = array(
				Resque_Job_Status::STATUS_WAITING => __d('cake_resque', 'waiting'),
				Resque_Job_Status::STATUS_RUNNING => __d('cake_resque', 'running'),
				Resque_Job_Status::STATUS_FAILED => __d('cake_resque', 'failed'),
				Resque_Job_Status::STATUS_COMPLETE => __d('cake_resque', 'complete')
			);

			$statusClass = array(
				Resque_Job_Status::STATUS_WAITING => 'info',
				Resque_Job_Status::STATUS_RUNNING => 'info',
				Resque_Job_Status::STATUS_FAILED => 'error',
				Resque_Job_Status::STATUS_COMPLETE => 'success'
			);

			if (Configure::read('CakeResque.Scheduler.enabled') === true) {
				$statusClass[ResqueScheduler\Job\Status::STATUS_SCHEDULED] = 'info';
				$statusName[ResqueScheduler\Job\Status::STATUS_SCHEDULED] = __d('cake_resque', 'scheduled');
			}

			$this->out(
				sprintf(
					__d('cake_resque', 'Status') . ' : <%1$s>%2$s</%1$s>',
					(isset($statusClass[$jobStatus]) ? $statusClass[$jobStatus] : 'warning'),
					isset($statusName[$jobStatus]) ? $statusName[$jobStatus] : __d('cake_resque', 'Unknown')
				)
			);

			if ($jobStatus === Resque_Job_Status::STATUS_FAILED) {
				$log = call_user_func(CakeResqueShell::$cakeResque . '::getFailedJobLog', $jobId);
				if (!empty($log)) {
					$this->hr();
					$this->out('<comment>' . __d('cake_resque', 'Failed job details') . '</comment>');
					$this->hr();
					foreach ($log as $key => $value) {
						$this->out(sprintf("<info>%-10s: </info>", strtoupper($key)), 0);
						if (is_string($value)) {
							$this->out($value);
						} else {
							$this->out('');
							foreach ($value as $sKey => $sValue) {
								$this->out(sprintf("    <info>%5s : </info>", $sKey), 0);
								if (is_string($sValue)) {
									$this->out($sValue);
								} else {
									$this->out(str_replace("\n", "\n            ", var_export($sValue, true)));
								}
							}
						}
					}
				}
			}
		}

		$this->out('');
	}

/**
 * Clear a queue.
 *
 * Remove all jobs inside a queue. If more than one queue is present, it will prompt
 * the user which queue to clear via a menu.
 *
 * If the queues are empty, they are removed from the queues list.
 *
 * @since 3.3.0
 * @return bool False is clearing the queues fails.
 */
	public function clear() {
		$this->out('<info>' . __d('cake_resque', 'Clearing queues') . '</info>');

		// List of all queues
		$queues = array_unique(call_user_func(CakeResqueShell::$cakeResque . '::getQueues'));
		if (empty($queues)) {
			$this->out(__d('cake_resque', 'There is no queues to clear'));
			return false;
		}

		$queueIndex = array();
		if (isset($this->args[0])) {
			if (in_array($this->args[0], $queues)) {
				$queueIndex[] = array_search($this->args[0], $queues) + 1;
			}
		} else {
			if (!$this->params['all'] && count($queues) > 1) {
				$this->out(__d('cake_resque', 'Queues list') . ':');
				$i = 1;
				foreach ($queues as $queue) {
					$this->out(sprintf("    [%3d] - %-'.20s<bold>%'.9s</bold> jobs", $i++, $queue, number_format(call_user_func_array(CakeResqueShell::$cakeResque . '::getQueueSize', array($queue)))));
				}

				$options = range(1, $i - 1);

				if ($i > 2) {
					$this->out('    [all] - ' . __d('cake_resque', 'Clear all queues'));
					$options[] = 'all';
				}

				$in = $this->in(__d('cake_resque', 'Queue to clear') . ': ', $options);
				if ($in == 'all') {
					$queueIndex = range(1, count($queues));
				} else {
					$queueIndex[] = $in;
				}

			} else {
				$queueIndex = range(1, count($queues));
			}
		}

		foreach ($queueIndex as $index) {
			$queue = $queues[$index - 1];

			$this->out(__d('cake_resque', 'Clearing %s ... ', $queue), 0);

			$cleared = call_user_func_array(CakeResqueShell::$cakeResque . '::clearQueue', array($queue));

			if ($cleared) {
				call_user_func_array(CakeResqueShell::$cakeResque . '::removeQueue', array($queue));
				$this->out('<success>' . __d('cake_resque', 'Done') . '</success>');
			} else {
				$this->out('<error>' . __d('cake_resque', 'Fail') . '</error>');
			}
		}

		return true;
	}

/**
 * Reset workers statuses.
 *
 * Note: The workers status is conveniently stored by ResqueStatus.
 *
 * @since 3.3.7
 * @return void
 * @see ResqueStatus\ResqueStatus::clearWorkers()
 * @see ResqueStatus\ResqueStatus::unregisterSchedulerWorker()
 */
	public function reset() {
		$ResqueStatus = $this->ResqueStatus;

		$this->debug(__d('cake_resque', 'Emptying the worker database'));
		$ResqueStatus->clearWorkers();
		$this->debug(__d('cake_resque', 'Unregistering the scheduler worker'));
		$ResqueStatus->unregisterSchedulerWorker();
		$this->out('<success>' . __d('cake_resque', 'CakeResque state has been reseted') . '</success>');
	}

/**
 * Validate command line options.
 *
 * Also, print the errors.
 *
 * @param array $args Command line arguments used to start the worker with.
 * @since 1.0
 * @return bool True if all options are valid, false otherwise.
 */
	protected function _validate($args = null) {
		$this->_runtime = ($args === null) ? $this->params : $args;

		$errors = array();

		if (!isset($this->_runtime['type'])) {
			$this->_runtime['type'] = 'regular';
		}

		if (!isset($this->_runtime['debug'])) {
			$this->_runtime['debug'] = false;
		}

		// Validate Log path
		$this->_runtime['log'] = isset($this->_runtime['log'])
		? $this->_runtime['log']
		: (Configure::read('CakeResque.Scheduler.log') && $this->_runtime['type'] === 'scheduler'
			? Configure::read('CakeResque.Scheduler.log')
			: Configure::read('CakeResque.Worker.log')
		);
		if (substr($this->_runtime['log'], 0, 2) == './') {
			$this->_runtime['log'] = TMP . 'logs' . DS . substr($this->_runtime['log'], 2);
		} elseif (substr($this->_runtime['log'], 0, 1) != '/') {
			$this->_runtime['log'] = TMP . 'logs' . DS . $this->_runtime['log'];
		}

		// Validate Interval
		$this->_runtime['interval'] = isset($this->_runtime['interval'])
		? $this->_runtime['interval']
		: (Configure::read('CakeResque.Scheduler.Worker.interval') && $this->_runtime['type'] === 'scheduler'
			? Configure::read('CakeResque.Scheduler.Worker.interval')
			: Configure::read('CakeResque.Worker.interval')
		);
		if (!is_numeric($this->_runtime['interval'])) {
			$errors[] = __d('cake_resque', 'Interval time [%s] is not valid. Please enter a valid number', $this->_runtime['interval']);
		} else {
			$this->_runtime['interval'] = (int)$this->_runtime['interval'];
		}

		// Validate workers number
		$this->_runtime['workers'] = isset($this->_runtime['workers']) ? $this->_runtime['workers'] : Configure::read('CakeResque.Worker.workers');
		if (!is_numeric($this->_runtime['workers'])) {
			$errors[] = __d('cake_resque', 'Workers number [%s] is not valid. Please enter a valid number', $this->_runtime['workers']);
		} else {
			$this->_runtime['workers'] = (int)$this->_runtime['workers'];
		}

		$this->_runtime['queue'] = isset($this->_runtime['queue']) ? $this->_runtime['queue'] : Configure::read('CakeResque.Worker.queue');

		// Validate user
		if (isset($this->_runtime['user'])) {
			$this->_runtime['user'] = $this->_runtime['user'];
		} elseif (Configure::read('CakeResque.Worker.user')) {
			$this->_runtime['user'] = Configure::read('CakeResque.Worker.user');
		} else {
			$user = $this->__getProcessOwner();
			$this->_runtime['user'] = empty($user) ? get_current_user() : $user;
		}

		$this->_runtime['verbose'] = isset($this->params['verbose']) ? $this->params['verbose'] : Configure::read('CakeResque.Worker.verbose');

		$output = array();
		exec('id ' . $this->_runtime['user'] . ' 2>&1', $output, $status);
		if ($status != 0) {
			$errors[] = __d('cake_resque', 'User [%s] does not exists. Please enter a valid system user', $this->_runtime['user']);
		}

		$this->_runtime['Log']['handler'] = isset($this->_runtime['log-handler'])
		? $this->_runtime['log-handler']
		: (Configure::read('CakeResque.Scheduler.Log.handler') && $this->_runtime['type'] === 'scheduler'
			? Configure::read('CakeResque.Scheduler.Log.handler')
			: Configure::read('CakeResque.Log.handler')
		);

		$this->_runtime['Log']['target'] = isset($this->_runtime['log-handler-target'])
		? $this->_runtime['log-handler-target']
		: (Configure::read('CakeResque.Scheduler.Log.target') && $this->_runtime['type'] === 'scheduler'
			? Configure::read('CakeResque.Scheduler.Log.target')
			: Configure::read('CakeResque.Log.target')
		);
		if (substr($this->_runtime['Log']['target'], 0, 2) == './') {
			$this->_runtime['Log']['target'] = TMP . 'logs' . DS . substr($this->_runtime['Log']['target'], 2);
		}

		if (!empty($errors)) {
			foreach ($errors as $error) {
				$this->err('<error>' . __d('cake_resque', 'Error') . ':</error> ' . $error);
			}
			$this->out();
		}
		return empty($errors);
	}

/**
 * Output debugging information.
 *
 * @param string $string Debug message to display
 * @return void
 */
	public function debug($string) {
		if ($this->params['verbose']) {
			$this->out('<success>[DEBUG] ' . $string . '</success>', 1, Shell::VERBOSE);
		}
	}

/**
 * Return the php-resque executable file.
 *
 * Maintain backward compatibility, as newer version of php-resque has that file
 * in another location.
 *
 * @param string $base Folder path for php-resque.
 * @since 3.3.2
 * @return string Relative path to php-resque executable file.
 */
	protected function _getResqueBinFile($base) {
		$paths = array(
			'bin' . DS . 'resque',
			'bin' . DS . 'resque.php',
			'resque.php'
		);

		foreach ($paths as $path) {
			if (file_exists($base . DS . $path)) {
				return '.' . DS . $path;
			}
		}
		return '.' . DS . 'resque.php';
	}

/**
 * Return kill command syntax, intended to be used with exec().
 *
 * @param string $signal Kill Signal.
 * @param string $pid Process id.
 * @since 3.3.4
 * @codeCoverageIgnore
 * @return array
 */
	protected function _kill($signal, $pid) {
		$output = array();
		$message = exec(sprintf('/bin/kill -%s %s 2>&1', $signal, $pid), $output, $code);
		return array('code' => $code, 'message' => $message);
	}

/**
 * Outputs the last part of a log file.
 *
 * @param string $path Path to the file to tail.
 * @since 3.3.6
 * @codeCoverageIgnore
 * @return void
 */
	protected function _tail($path) {
		$this->_exec('tail -f ' . escapeshellarg($path));
	}

/**
 * Execute a shell command.
 *
 * @param string $cmd Command to execute.
 * @since 3.3.6
 * @codeCoverageIgnore
 * @return void
 */
	protected function _exec($cmd) {
		passthru($cmd);
	}

/**
 * Check if the worker has started.
 *
 * @param string $pidFile Path to the file containing the worker PID.
 * @since 3.3.6
 * @codeCoverageIgnore
 * @return mixed Worker PID if worker is started, false otherwise.
 */
	protected function _checkStartedWorker($pidFile) {
		$pid = false;
		if (file_exists($pidFile) && false !== $pid = file_get_contents($pidFile)) {
			unlink($pidFile);
			return (int)$pid;
		}
		return false;
	}

/**
 * Get the username of the current process owner.
 *
 * @since 4.0.0
 * @codeCoverageIgnore
 * @return string Username of the current process owner if found, false otherwise.
 */
	private function __getProcessOwner() {
		if (function_exists('posix_getpwuid')) {
			$a = posix_getpwuid(posix_getuid());
			return $a['name'];
		} else {
			$user = trim(exec('whoami', $o, $code));
			if ($code === 0) {
				return $user;
			}
			return false;
		}

		return false;
	}
}
