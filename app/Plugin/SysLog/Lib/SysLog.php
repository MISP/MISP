<?php
/**
 * Syslog Storage stream for Logging
 *
 * PHP versions 4 and 5
 *
 * Copyright 2008-2010, UGR Works Limited.
 *
 * Licensed under The MIT License
 * Redistributions of files must retain the above copyright notice.
 *
 * @copyright    Copyright 2008-2010, UGR Works Limited
 * @package       sunshine
 * @subpackage    sunshine.cake.libs.log
 * @license       MIT License (http://www.opensource.org/licenses/mit-license.php)
 */

/**
 * SysLog for Logging.
 *
 * @package sunshine
 * @subpackage sunshine.cake.libs.log
 */
class SysLog
{
    /** @var bool */
    private $_log;

    /**
     * Constructs a new SysLog Logger.
     *
     * Options
     *
     * - `ident` the ident to be added to each message.
     * - `facility` what type of application is recording a message. Default: LOG_LOCAL0. LOG_USER if Windows.
     * - `to_stderr` if true, print log message also to standard error
     *
     * @param array $options Options for the SysLog, see above.
     * @return void
     */
    public function __construct($options = array())
    {
        $options += array('ident' => LOGS, 'facility' => LOG_LOCAL0, 'to_stderr' => true);
        $option = LOG_PID; // include PID with each message
        if ($options['to_stderr']) {
            $option |= LOG_PERROR; // print log message also to standard error
        }
        $this->_log = openlog($options['ident'], $option, $options['facility']);
    }

    /**
     * Implements writing to the specified syslog
     *
     * @param string $type The type of log you are making.
     * @param string $message The message you want to log.
     * @return boolean success of write.
     */
    public function write($type, $message)
    {
        if (!$this->_log) {
            return false;
        }
        $debugTypes = array('notice', 'info', 'debug');
        $priority = LOG_INFO;
        if ($type == 'error' || $type == 'warning') {
            $priority = LOG_ERR;
        } else if (in_array($type, $debugTypes)) {
            $priority = LOG_DEBUG;
        }
        $output = date('Y-m-d H:i:s') . ' ' . ucfirst($type) . ': ' . $message;
        return syslog($priority, $output);
    }
}
