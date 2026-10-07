<?php

/**
 * MsgdPlug Plugin
 *
 * @author     TETRAPI SA, Lino Pacheco
 * @license    AGPL-3.0
 */

declare(strict_types=1);

App::uses('CakeLog', 'Log');
App::uses('Configure', 'Core');

/**
 * Logger utility for recording plugin events and handling exceptions.
 *
 * @package    MsgdPlug
 * @subpackage MsgdPlug.Lib.Utility
 */
final class MsgdLoggerUtility
{
    /**
     * Maximum allowed length for a single log message.
     */
    public const MAX_LOG_LENGTH = 8192;

    /**
     * Cleans and writes a message to the application log.
     *
     * @param string $logSeverity
     * @param string $logMessage
     *
     * @return void
     */
    public static function log(
        string $logSeverity,
        string $logMessage
    ): void {
        $sanitizedLogSeverity = strtolower(trim($logSeverity));

        if ($sanitizedLogSeverity === 'debug') {
            $isDebugLogEnabled = (bool)Configure::read(
                MsgdPluginConfigEnum::debug->value
            );

            if (!$isDebugLogEnabled) {
                return;
            }
        }

        if ($logMessage === '') {
            return;
        }

        $utf8LogMessage = mb_scrub($logMessage, 'UTF-8');

        if (mb_strlen($utf8LogMessage, 'UTF-8') > self::MAX_LOG_LENGTH) {
            $utf8LogMessage = mb_substr($utf8LogMessage, 0, self::MAX_LOG_LENGTH, 'UTF-8') . '... [TRUNCATED]';
        }

        $singleLineMessage = (string)preg_replace(
            '/[\r\n\t]+/',
            ' ',
            $utf8LogMessage
        );

        $sanitizedLogMessage = (string)preg_replace(
            '/\p{C}/u',
            '',
            $singleLineMessage
        );

        $trimmedLogMessage = trim($sanitizedLogMessage);

        if ($trimmedLogMessage === '') {
            return;
        }

        $targetScope = self::resolveScope($sanitizedLogSeverity);

        CakeLog::write(
            $sanitizedLogSeverity,
            'MsgdPlug: ' . $trimmedLogMessage,
            [$targetScope]
        );
    }

    /**
     * Resolves the target scope based on severity.
     *
     * @param string $severity
     *
     * @return string
     */
    private static function resolveScope(string $severity): string
    {
        return match ($severity) {
            'debug', 'info' => 'msgd_debug',
            'warning', 'notice' => 'msgd_warning',
            default => 'msgd_error',
        };
    }

    /**
     * Logs details and stack traces for caught exceptions.
     *
     * @param Throwable $exception
     * @param string $executionContext
     *
     * @return void
     */
    public static function logException(
        Throwable $exception,
        string $executionContext = ''
    ): void {
        $trimmedContext = trim($executionContext);

        $cleanContext = $trimmedContext !== ''
            ? (string)preg_replace(
                '/[\r\n\t]+/',
                ' ',
                $trimmedContext
            )
            : '';

        $formattedContextSuffix = $cleanContext !== ''
            ? sprintf(
                ' [Context: %s]',
                mb_substr($cleanContext, 0, 255, 'UTF-8')
            )
            : '';

        self::log(
            'error',
            sprintf(
                'Critical exception thrown%s. Error: %s in %s on line %d. Stack Trace: %s',
                $formattedContextSuffix,
                $exception->getMessage(),
                $exception->getFile(),
                $exception->getLine(),
                $exception->getTraceAsString()
            )
        );
    }
}
