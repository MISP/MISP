<?php

App::uses('ExceptionRenderer', 'Error');

class AppExceptionRenderer extends ExceptionRenderer {

    public function __construct($exception) {
        $this->controller = $this->_getController($exception);

        if (method_exists($this->controller, 'appError')) {
            $this->controller->appError($exception);
            return;
        }
        $method = $template = Inflector::variable(str_replace('Exception', '', get_class($exception)));
        $code = $exception->getCode();

        $methodExists = method_exists($this, $method);
        if ($exception instanceof CakeException && !$methodExists) {
            $this->_customErrorLogging($exception);
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
        $message = $exception->getMessage();
        $errorDetection = [
            'Maximum execution time of' => 'timeout',
            'Allowed memory size of' => 'out of memory'
        ];
        $user = $this->controller->Auth->user();
        $ua = env('HTTP_USER_AGENT');
        $source = $this->controller->IndexFilter->isRest() ? 'API' : 'web UI';
        if (strpos($ua, 'MISP ') !== false) {
            $source = 'MISP sync';
        }
        foreach ($errorDetection as $search => $errorName) {
            if (strpos($message, $search) !== false) {
                $logMessage = sprintf(
                    '%s %s error triggered by User %s (%s) via the %s on %s.',
                    date('Y-m-d H:i:s'),
                    $errorName,
                    $user['id'],
                    $user['email'],
                    $source,
                    $this->controller->request->here()
                );
                file_put_contents(LOGS . 'fatal_error.log', $logMessage . PHP_EOL, FILE_APPEND);
                return true;
            }
        }
        return true;
    }
}