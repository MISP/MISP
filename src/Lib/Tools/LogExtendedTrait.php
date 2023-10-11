<?php

namespace App\Lib\Tools;

use Cake\Log\LogTrait;
use Exception;

trait LogExtendedTrait
{
    use LogTrait;
    /**
     * Log exception with backtrace and with nested exceptions.
     *
     * @param string $message
     * @param Exception $exception
     * @param int $type
     * @return bool
     */
    protected function logException($message, Exception $exception, $type = LOG_ERR)
    {
        // If Sentry is installed, send exception to Sentry
        if (function_exists('\Sentry\captureException') && $type === LOG_ERR) {
            \Sentry\captureException($exception);
        }

        $message .= "\n";

        do {
            $message .= sprintf("[%s] %s", get_class($exception), $exception->getMessage());
            $message .= "\nStack Trace:\n" . $exception->getTraceAsString();
            $exception = $exception->getPrevious();
        } while ($exception !== null);

        return $this->log($message, $type);
    }
}
