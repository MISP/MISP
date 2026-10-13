<?php

/**
 * MsgdPlug Plugin
 *
 * @author     TETRAPI SA, Lino Pacheco
 * @license    AGPL-3.0
 */

declare(strict_types=1);

App::uses('AppHelper', 'View/Helper');
App::uses('HtmlHelper', 'View/Helper');
App::uses('View', 'View');
App::uses('CakeRequest', 'Network');

/**
 * Helper responsible for injecting plugin assets, templates, and configs into MISP views.
 *
 * @property View $_View
 * @property HtmlHelper $Html
 * @property CakeRequest $request
 *
 * @package    MsgdPlug
 * @subpackage MsgdPlug.View.Helper
 */
final class MsgdInjectorHelper extends AppHelper
{
    /**
     * @var array<int, string>
     */
    public $helpers = ['Html'];

    /**
     * Prevents duplicate asset injection during the same request.
     */
    private static bool $alreadyInjected = false;

    /**
     * Injects plugin assets, templates, and JavaScript modules into supported MISP views.
     *
     * @return string
     */
    public function injectPlugin(): string
    {
        if (self::$alreadyInjected) {
            return '';
        }

        try {
            /** @var string|null $requestControllerName */
            $requestControllerName = $this->request->params['controller'] ?? null;

            /** @var string|null $requestActionName */
            $requestActionName = $this->request->params['action'] ?? null;

            if (!is_string($requestControllerName) || !is_string($requestActionName)) {
                return '';
            }

            $supportedAction = MsgdMispActionEnum::tryFromLower($requestActionName);

            if ($supportedAction === null) {
                return '';
            }

            self::$alreadyInjected = true;

            $renderedHtmlSegments = [
                $this->renderElement(MsgdPluginFileEnum::msgd_templates_ctp),
                $this->renderElement(MsgdPluginFileEnum::msgd_utils_ctp, ['urls' => $this->buildUrlMap()]),
            ];

            $actionElement = $supportedAction->getActionElement();
            $renderedHtmlSegments[] = $this->renderElement($actionElement, ['action' => $supportedAction]);

            $nonEmptyHtmlSegments = array_filter(
                $renderedHtmlSegments,
                static fn(string $htmlSegment): bool => trim($htmlSegment) !== ''
            );

            return implode("\n", $nonEmptyHtmlSegments);
        } catch (Throwable $exception) {
            MsgdLoggerUtility::logException(
                $exception,
                '[MsgdInjectorHelper] injectPlugin rendering execution context'
            );

            return '';
        }
    }

    /**
     * Generates a map of URLs used by frontend scripts.
     *
     * @return array<string, string>
     */
    private function buildUrlMap(): array
    {
        return [
            MsgdPluginActionEnum::check_user_permission->getRouteKey() => (string) $this->Html->url([
                'plugin' => 'msgd_plug',
                'controller' => 'msgd_api',
                'action' => MsgdPluginActionEnum::check_user_permission->value,
            ]),

            MsgdPluginActionEnum::process_groups->getRouteKey() => (string) $this->Html->url([
                'plugin' => 'msgd_plug',
                'controller' => 'msgd_api',
                'action' => MsgdPluginActionEnum::process_groups->value,
            ]),

            MsgdPluginActionEnum::get_sharing_groups->getRouteKey() => (string) $this->Html->url([
                'plugin' => 'msgd_plug',
                'controller' => 'msgd_api',
                'action' => MsgdPluginActionEnum::get_sharing_groups->value,
            ]),

            MsgdPluginActionEnum::check_blueprint->getRouteKey() => (string) $this->Html->url([
                'plugin' => 'msgd_plug',
                'controller' => 'msgd_api',
                'action' => MsgdPluginActionEnum::check_blueprint->value,
            ]),

            MsgdPluginActionEnum::get_blueprint_rules_groups->getRouteKey() => (string) $this->Html->url([
                'plugin' => 'msgd_plug',
                'controller' => 'msgd_api',
                'action' => MsgdPluginActionEnum::get_blueprint_rules_groups->value,
            ]),

            MsgdMispActionEnum::view->getRouteKey() => (string) $this->Html->url([
                'plugin' => false,
                'controller' => 'sharing_groups',
                'action' => MsgdMispActionEnum::view->value,
            ]),
        ];
    }

    /**
     * Renders a View element and catches any rendering errors.
     *
     * @param MsgdPluginFileEnum|null $elementFile
     * @param array{
     *     urls?: array<string, string>,
     *     action?: MsgdMispActionEnum
     * } $elementData
     *
     * @return string
     */
    private function renderElement(?MsgdPluginFileEnum $elementFile, array $elementData = []): string
    {
        if ($elementFile === null) {
            return '';
        }

        $elementPath = $elementFile->getPath();

        try {
            return (string) $this->_View->element($elementPath, $elementData);
        } catch (Throwable $exception) {
            MsgdLoggerUtility::logException(
                $exception,
                sprintf("[MsgdInjectorHelper] Rendering View element '%s'", $elementPath)
            );

            return '';
        }
    }
}
