<?php

/**
 * MsgdPlug Plugin
 *
 * @author     TETRAPI SA, Lino Pacheco
 * @license    AGPL-3.0
 */

declare(strict_types=1);

App::uses('CakeLog', 'Log');
App::uses('View', 'View');
App::uses('Configure', 'Core');
App::uses('CakeEvent', 'Event');
App::uses('CakeEventManager', 'Event');
App::uses('MsgdInjectorHelper', 'MsgdPlug.View/Helper');

/**
 * MsgdPlug Bootstrap.
 *
 * Initializes the plugin and listens to MISP's view rendering event
 * to automatically inject required JavaScript and CSS assets into supported pages.
 *
 * @package    MsgdPlug
 * @subpackage MsgdPlug.Config
 */

CakeLog::config('msgd_error_stream', [
    'engine' => 'FileLog',
    'types' => ['error', 'critical', 'alert', 'emergency'],
    'scopes' => ['msgd_error'],
    'file' => 'msgd_error.log',
]);

CakeLog::config('msgd_warning_stream', [
    'engine' => 'FileLog',
    'types' => ['warning', 'notice'],
    'scopes' => ['msgd_warning'],
    'file' => 'msgd_warning.log',
]);

CakeLog::config('msgd_debug_stream', [
    'engine' => 'FileLog',
    'types' => ['debug', 'info'],
    'scopes' => ['msgd_debug'],
    'file' => 'msgd_debug.log',
]);

/**
 * Registers the native PHP autoloader for the MsgdPlug architecture.
 *
 * Automatically loads classes from DTO, Enum, Service, and Utility directories.
 *
 * @param string $className
 *
 * @return void
 */
spl_autoload_register(static function (string $className): void {
    if (!str_starts_with($className, 'Msgd')) {
        return;
    }

    foreach (['DTO', 'Enum', 'Service', 'Utility', 'Voter'] as $directory) {
        $filePath = __DIR__ . '/../Lib/' . $directory . '/' . $className . '.php';

        if (file_exists($filePath)) {
            require_once $filePath;
            return;
        }
    }
});

$isPluginEnabled = (bool)Configure::read(MsgdPluginConfigEnum::enable->value);

if ($isPluginEnabled) {
    CakeEventManager::instance()->attach(
    /**
     * Listens to the View.afterRender event to inject required assets.
     *
     * @param CakeEvent $renderEvent
     *
     * @return void
     */
        static function (CakeEvent $renderEvent): void {
            static $alreadyInjected = false;

            if ($alreadyInjected) {
                return;
            }

            /** @var View|null $viewInstance */
            $viewInstance = $renderEvent->subject();

            if (!$viewInstance instanceof View) {
                return;
            }

            $params = $viewInstance->request->params;
            $requestControllerName = $params['controller'] ?? null;
            $requestActionName = $params['action'] ?? null;

            if (!is_string($requestControllerName) || !is_string($requestActionName)) {
                return;
            }

            if (strlen($requestControllerName) > 100 || strlen($requestActionName) > 100) {
                return;
            }

            $normalize = static fn(string $value): string => strtolower(
                (string)preg_replace('/[^a-zA-Z0-9*]/', '', $value)
            );

            $requestControllerNormalized = $normalize($requestControllerName);
            $requestActionLower = strtolower(trim($requestActionName));

            $supportedAction = MsgdMispActionEnum::tryFromLower($requestActionLower);

            if ($supportedAction === null) {
                return;
            }

            $rawWhitelist = Configure::read(
                MsgdPluginConfigEnum::controller_whitelist->value
            );
            $whitelistConfig = is_scalar($rawWhitelist) ? (string)$rawWhitelist : '';

            if ($whitelistConfig === '') {
                return;
            }

            $items = explode(',', $whitelistConfig);
            $normalizedItems = array_map($normalize, $items);
            $allowedControllers = array_filter(
                $normalizedItems,
                static fn(string $item): bool => $item !== ''
            );

            if (
                !in_array('*', $allowedControllers, true)
                && !in_array($requestControllerNormalized, $allowedControllers, true)
            ) {
                return;
            }

            $alreadyInjected = true;

            try {
                $msgdInjectorHelper = $viewInstance->Helpers->load(
                    MsgdPluginFileEnum::msgd_injector_php->getPath()
                );

                if (!$msgdInjectorHelper instanceof MsgdInjectorHelper) {
                    MsgdLoggerUtility::log(
                        'warning',
                        '[MsgdPlug bootstrap] Failed to load MsgdInjectorHelper or invalid instance type.'
                    );
                    return;
                }

                /** @var string $injectedAssetPayload */
                $injectedAssetPayload = $msgdInjectorHelper->injectPlugin();

                if (!empty($injectedAssetPayload)) {
                    $currentOutput = $viewInstance->fetch('content');
                    $viewInstance->assign('content', $currentOutput . "\n" . $injectedAssetPayload);
                }
            } catch (Throwable $exception) {
                MsgdLoggerUtility::logException(
                    $exception,
                    '[MsgdPlug bootstrap] Event Hook View.afterRender Injection Pipeline'
                );
            }
        },
        'View.afterRender'
    );
}
