<?php

App::uses('ExceptionRenderer', 'Error');

class AppExceptionRenderer extends ExceptionRenderer {

    /**
     * Error types that end the request. `error_get_last()` reporting one of these
     * means we are running inside the fatal error shutdown chain
     * (App::shutdown() -> App::_checkFatalError() -> ErrorHandler::handleFatalError()).
     */
    const FATAL_ERROR_TYPES = E_ERROR | E_PARSE | E_CORE_ERROR | E_COMPILE_ERROR | E_USER_ERROR;

    /**
     * Extra memory (in kilobytes) requested before touching the database, on top of
     * the `Error.extraFatalErrorMemory` headroom App::shutdown() already granted.
     */
    const FATAL_ERROR_EXTRA_MEMORY_KB = 8192;

    public function __construct($exception) {
        $this->controller = $this->_getController($exception);

        // Has to happen before the `appError` shortcut and before the exception is
        // classified below: on a production instance (debug disabled) the fatal is
        // wrapped into an InternalErrorException, which is not a CakeException and
        // carries the generic 'Internal Server Error' message, so neither the
        // classification below nor the exception message can be relied upon.
        $this->_customErrorLogging($exception);

        if (method_exists($this->controller, 'appError')) {
            $this->controller->appError($exception);
            return;
        }
        $method = $template = Inflector::variable(str_replace('Exception', '', get_class($exception)));
        $code = $exception->getCode();

        $methodExists = method_exists($this, $method);
        if ($exception instanceof CakeException && !$methodExists) {
            $method = '_cakeError';
            if (empty($template) || $template === 'internalError') {
                $template = 'error500';
            }
        } elseif ($exception instanceof PDOException) {
            $method = 'pdoError';
            $template = 'pdo_error';
            $code = 500;
        } elseif (!$methodExists) {
            $method = 'error500';
            if ($code >= 400 && $code < 500) {
                $method = 'error400';
            }
        }

        $isNotDebug = !Configure::read('debug');
        if ($isNotDebug && $method === '_cakeError') {
            $method = 'error400';
        }
        if ($isNotDebug && $code == 500) {
            $method = 'error500';
        }
        $this->template = $template;
        $this->method = $method;
        $this->error = $exception;
    }

    protected function _customErrorLogging($exception): bool
    {
        $errorDetection = [
            'Maximum execution time of' => 'timeout',
            'Allowed memory size of' => 'out of memory'
        ];

        // Prefer the raw PHP error over the exception message: the exception is only
        // a stand-in created by ErrorHandler::handleFatalError() and it only carries
        // the original description while `debug` is enabled.
        $message = $exception->getMessage();
        $lastError = error_get_last();
        if (is_array($lastError) && ($lastError['type'] & self::FATAL_ERROR_TYPES)) {
            $message = $lastError['message'];
        }

        foreach ($errorDetection as $search => $errorName) {
            if (strpos($message, $search) === false) {
                continue;
            }

            list($userId, $userEmail) = $this->_fatalErrorUser();
            $logMessage = sprintf(
                '%s %s error triggered by User %s (%s) via the %s on %s.',
                date('Y-m-d H:i:s'),
                $errorName,
                $userId,
                $userEmail,
                $this->_fatalErrorSource(),
                $this->_fatalErrorUrl()
            );

            // The flat file stays the guaranteed fallback and is written first, before
            // anything that could itself fail during the shutdown.
            file_put_contents(LOGS . 'fatal_error.log', $logMessage . PHP_EOL, FILE_APPEND);
            $this->_logFatalErrorToDatabase($userId, $logMessage, $message);
            return true;
        }
        return true;
    }

    /**
     * Record the fatal error in the MISP application log, so that it shows up in
     * Administration -> Logs rather than only in a file on disk.
     *
     * Everything here is best effort: we are running inside a shutdown function that
     * was reached because the request ran out of memory or out of time, so the model
     * layer or the database connection may well be unusable. A failure here must
     * never replace the fatal error with an error of its own - the flat file written
     * by the caller remains the fallback.
     *
     * @param int|string $userId
     * @param string $logMessage
     * @param string $errorMessage
     * @return void
     */
    protected function _logFatalErrorToDatabase($userId, $logMessage, $errorMessage)
    {
        try {
            // An out of memory fatal leaves no room to allocate anything. App::shutdown()
            // already added `Error.extraFatalErrorMemory` (4 MB by default) before this
            // chain was entered; give the database write some more so it cannot fatal a
            // second time, this time inside the error handler itself.
            App::increaseMemoryLimit(self::FATAL_ERROR_EXTRA_MEMORY_KB);

            $log = ClassRegistry::init('Log');
            $log->createLogEntry(
                'SYSTEM',
                'error',
                'User',
                (int)$userId,
                $logMessage,
                $errorMessage
            );
        } catch (Throwable $e) {
            // Deliberately swallowed - see the docblock. The flat file already has the entry.
            try {
                file_put_contents(
                    LOGS . 'fatal_error.log',
                    sprintf('%s could not write the fatal error to the application log: %s', date('Y-m-d H:i:s'), $e->getMessage()) . PHP_EOL,
                    FILE_APPEND
                );
            } catch (Throwable $ignored) {
            }
        }
    }

    /**
     * @return array [user id, user e-mail]
     */
    protected function _fatalErrorUser(): array
    {
        try {
            if (isset($this->controller->Auth)) {
                $user = $this->controller->Auth->user();
                if (!empty($user)) {
                    return [$user['id'] ?? 0, $user['email'] ?? 'unknown'];
                }
            }
        } catch (Throwable $e) {
            // fall through
        }
        return [0, 'unknown'];
    }

    protected function _fatalErrorSource(): string
    {
        $ua = (string)env('HTTP_USER_AGENT');
        if (strpos($ua, 'MISP ') !== false) {
            return 'MISP sync';
        }
        try {
            if (isset($this->controller->IndexFilter) && $this->controller->IndexFilter->isRest()) {
                return 'API';
            }
        } catch (Throwable $e) {
            // fall through
        }
        return 'web UI';
    }

    protected function _fatalErrorUrl(): string
    {
        try {
            if (isset($this->controller->request)) {
                return (string)$this->controller->request->here();
            }
        } catch (Throwable $e) {
            // fall through
        }
        return (string)env('REQUEST_URI');
    }
}
