##Changelog

###**v4.1.2** [2015-03-28]

* [fix] Fix#80: Only use DEBUG_BACKTRACE_IGNORE_ARGS for PHP_VERSION >= 5.3.6 (bis)

###**v4.1.1** [2015-01-28]

* [fix] Fix#80: Only use DEBUG_BACKTRACE_IGNORE_ARGS for PHP_VERSION >= 5.3.6

###**v4.1.0** [2014-08-03]

* [new] Fix#57: Add Redis auth
* [fix] Fix#63: CakeResque should now be installed as a dependency to your main app.
* [fix] Fix#62: Optimize `AppShell::perform()`. Update the `perform()` method inside your AppShell class to

		public function perform() {
			$this->initialize();
			return $this->runCommand($this->args[0], $this->args);
		}

* [fix] Stopping a worker should also removed all empty queues associated to it
* Various improvement and bugfixes

> **NOTE**: All CakeResque dependencies are now installed inside your app `Vendor` dir, and not inside `Plugin/CakeResque/vendor` anymore.

###**v4.0.2** [2013-11-06]

* [fix] Uses `App::uses` in CakeResqueBootstrap

###**v4.0.1** [2013-10-29]

* [new] Add setting to set a custom dir for the workers PID files

###**v4.0.0** [2013-10-25]

* [new] Fix #20: Ease personalized plugin configuration [@bar]
* [fix] Fix #33: Don't use `sudo` when the current user is already the target user
* [fix] Default process owner is the one running the webserver, and not the one owning the file
* [fix] Fix #25: Workers now works with exotic directory structure

###**v3.3.8** [2013-08-22]

* [fix] Handle custom cake `app` folder name

###**v3.3.7** [2013-07-07]

* [new] Add `reset` to reset CakeResque internal state
* [removed] Remove `--debug` option, in favor of `--verbose`
* [fix] Some text formatting and other minor fixes

###**v3.3.6** [2013-05-18]

* [new] `restart` now takes into account the workers your stopped and started just before.
* [new] More reliable worker detection on `start` and `startscheduler`
* [fix] Upgrade CakeResqueBootstrap file with Cake2 version
* [new] Add unit tests. Code coverage can be tracked on coveralls.io

> **NOTE**: Workers status are stocked in a different format. Please *stop all your workers* first before updating.


###**v3.3.5** [2013-05-07]

* [fix] Call kill command using an absolute path [bar]

###**v3.3.4** [2013-04-30]

* [fix] Stop worker gracefully by sending it a SIGNAL, instead of killing the process

###**v3.3.3** [2013-04-24]

* [fix] Handle setup with exotic app folder name

###**v3.3.2** [2013-04-17]

* [new] Add `--debug`

###**v3.3.1** [2013-04-14]

* [new] Add `--verbose` option when starting worker. Default log mode downgraded from verbose to normal.

###**v3.3.0** [2013-04-13]

* [new] Add `clear` command to clear queues' jobs

###**v3.2.4** [2013-02-27]

* [fix] Namespace was changed in ResqueScheduler

###**v3.2.3** [2013-02-12]

* [fix] Invalid jobs number for queues stats
* [fix] Add example of using custom user when starting worker

###**v3.2.2** [2013-02-10]

* [fix] 100% test code coverage for existing tests

###**v3.1.1** [2013-02-07]

* [change] More accurate error message when starting workers fail
* [fix] Fix error while loading the Resque Job Creator class

###**v3.1.0** [2013-02-06]

* [new] Add tests & refactor some class to make them more testable
* [new] Use Travis CI
* [change] Update composer to make plugin installable as a CakePHP Plugin

###**v3.0.4** [2013-02-01]

* [new] Display total number of scheduled jobs in stats

###**v3.0.3** [2013-01-30]

* [fix] Load ResqueScheduler library even if scheduler is disabled to prevent class not found

###**v3.0.2** [2013-01-30]

* [fix] Load missing resque library files
* [fix] More accurate detection of workers status
* [change] Reove redundant fiels include

###**v3.0.1** [2013-01-30]

* [change] Rename default log files for consistency

###**v3.0.0** [2013-01-30]

* [new] Add `enqueueAt()` and `enqueueIn()` for scheduled jobs
* [new] Display pending jobs count for each queues in `stats`
* [new] Display message when a queue is not monitored by a worker, in `stats`
* [new] Display error message when resque library files are not found, instead of fatal error

> Scheduled Jobs are disabled by default. Activate them by setting `CakeResque.Scheduler.enabled` to `true` in the bootstrap file.
> Run `composer update` to update your dependencies
> See [upgrade notes]()http://www.kamisama.me/?p=495)

###**v2.2.1** [2012-10-24]

* [new] Add .pot file for i18n. Help for translation are welcomed.

###**v2.2.0** [2012-10-23]

* [fix] Tracking job not working properly
* [new] Display failed job details using `track` when job status is *fail*

> Require php-resque-ex **1.0.14**.
> Update dependencies with `composer update`


###**v2.1.0** [2012-10-16]

* [new] Add `track` command to track a job status

> A new `CakeResque.Job.track` setting has been added to the bootstrap file.
> It's the master value to enable the job tracking status.
> You can also enable/disable tracking on a per-job basis,
> by passing `true`/`false` as fourth argument when queueing job via `CakeResque::enqueue()`.
>
> Job status tracking is disabled by default.
> Job status is only kept for 24 hours.
> *Unknown* will be returned
>
> - when job ID is invalid,
> - when job status is expired,
> - or when job status tracking is disabled.




###**v2.0.0** [2012-10-14]

* [new] Add `pause` command to pause one or all worker
* [new] Add `resume` command to resume one or all paused worker
* [new] Add `cleanup` command to immediately terminate a worker's job
* [change] Add more documentation

###**v1.2.6** [2012-10-08]

* [new] Use your own php-resque library

###**v1.2.5** [2012-10-03]

* [fix] Strict Error warning when checking for existing user

###**v1.2.4** [2012-10-01]

* [new] Log Job ID for DebugKit resque panel

###**v1.2.3** [2012-10-01]

* [fix] Fix composer dependencies

###**v1.2.2** [2012-09-27]

* [new] Enqueuing a job return job id

###**v1.2.1** [2012-09-10]

* [Fix] Log correct method name when processing job

###**v1.2.0** [2012-09-08]

* [new] Add CakeResque proxy to enable jobs logging
> Refactor all your `Resque::enqueue()` call to `CakeResque::enqueue()`, to enable logging.
> Install [DebugKitEx](https://github.com/kamisama/DebugKitEx) to view jobs log via DebugKit.
> `Resque::enqueue()` still works.

###**v1.1.0** [2012-08-29]

* [new] Add `CakeResque.Redis.database` and `CakeResque.Redis.namespace` settings in bootstrap
> **database** to select the redis database (redis database are integer)
> **namespace** to set the keys namespace (key prefix)
> Add these new 2 keys to your bootstrap when you update
* [change] Remove CakeResqueComponent
> Remove it from $components in your AppController

###**v.1.0.0** [2012-08-27]

* [fix] Restart was ignoring workers when they have the same arguments
* [fix] Restart was duplicating workers
* [fix] Various fixes and formatting (@josegonzalez)
* [fix] Starting a worker with `start` now return if the worker was successfully created
* [new] Overwrite bootstrap in app/Lib (@josegonzalez)
* [new] Pass additional environement variable to Resque (@josegonzalez)
* [new] Use Composer to manage dependencies
* [new] Use php-resque-ex instead of php-resque
* [new] `--log` option added to `start`, to specify the path of the log file. Each worker can have its own log
* [new] New `--log-handler` and `log-handler-target` options for `start`, to use another log engine
* [new] `stop` now stop individual worker from a list. Use `--all` flag to stop all workers
* [new] `tail` command display a list of logs to monitor
* [new] All options are validated
* [new] Add a *Resque_Job_Creator* class in bootstrap, to handle all jobs creation
* [change] Remove `--tail` options on `start`, prefer the `tail` command
* [change] Format code to CakePHP coding standard
* [change] Documentation removed from README, refer to [website](http://cakeresque.kamisama.me)
* [change] Rename all files and classes to the plugin name : CakeResque
* [ui] Various fixes and formatting

###**v.0.81** [2012-05-09]

* [fix] Give the same name for workers count variable in all files

###**v.0.8** [2012-05-08]

* [new] `Load` Command to start a batch of queues defined in you bootstrap, at once

###**v.0.72** [2012-05-07]

* [fix] Fallback to Redisent when PhpRedis is not installed was broken

###**v.0.71** [2012-03-31]

* [fix] Shell outside Plugin folder where not found

###**v.0.7** [2012-03-31]

* [fix] Use user defined redis server configuration for resque


###**v.0.6** [2012-03-14]

* Removed jobs command
* Added CakePHP plugin syntax (*Plugin.Model*) when referencing classname: job classes doesn't have to be located in `app/Console/Command ` anymore, you can leave them in `PluginName/Console/Command`, as long as you extends the `AppShell` class, that contains a `perform` method
* Updated php-resque to latest version
* Added Redisent support: php-resque fallback to Redisent if phpRedis is not installed
* Enabled namespace for all resque keys in redis
* Changed cli `enqueue` command to accept the same arguments as the php one

###**v.0.5** [2012-02-19]

* `restart` now restore all workers with their options
