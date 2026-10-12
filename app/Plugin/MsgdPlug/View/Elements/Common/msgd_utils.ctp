<?php

/**
 * MsgdPlug Plugin
 *
 * @author     TETRAPI SA, Lino Pacheco
 * @license    AGPL-3.0
 */

declare(strict_types=1);

App::uses('Configure', 'Core');

/**
 * Passes backend settings and route URLs to the JavaScript runtime.
 *
 * @var array<string, string>|null $urls
 *
 * @package    MsgdPlug
 * @subpackage MsgdPlug.View.Elements.Common
 */

try {
    /** @var array<string, string> $urlsData */
    $urlsData = isset($urls) && is_array($urls) ? $urls : [];

    if ($urlsData === []) {
        MsgdLoggerUtility::log(
            'warning',
            '[MsgdPlug CTP: utils] The $urls array is missing or empty. Frontend API calls may fail.'
        );
    } else {
        $expectedRouteKeys = [
            MsgdPluginActionEnum::check_user_permission->getRouteKey(),
            MsgdPluginActionEnum::process_groups->getRouteKey(),
            MsgdPluginActionEnum::get_sharing_groups->getRouteKey(),
            MsgdPluginActionEnum::check_blueprint->getRouteKey(),
            MsgdPluginActionEnum::get_blueprint_rules_groups->getRouteKey(),
            MsgdMispActionEnum::view->getRouteKey(),
        ];

        $invalidRouteKeys = [];

        foreach ($expectedRouteKeys as $routeKey) {
            if (
                !isset($urlsData[$routeKey])
                || !is_string($urlsData[$routeKey])
                || trim($urlsData[$routeKey]) === ''
            ) {
                $invalidRouteKeys[] = $routeKey;
            }
        }

        if ($invalidRouteKeys !== []) {
            MsgdLoggerUtility::log(
                'warning',
                sprintf(
                    '[MsgdPlug CTP: utils] Missing or empty endpoint URLs detected for keys: %s',
                    implode(', ', $invalidRouteKeys)
                )
            );
        }
    }

    $utilitiesConfiguration = [
        'statusTypes' => [
            'SUCCESS' => MsgdPluginStatusEnum::success->value,
            'ERROR' => MsgdPluginStatusEnum::error->value,
            'INFO' => MsgdPluginStatusEnum::info->value,
            'WARNING' => MsgdPluginStatusEnum::warning->value,
        ],
        'routeKeys' => [
            'SG_VIEW_BASE_URL' => MsgdMispActionEnum::view->value,
            'CHECK_USER_PERMISSION' => MsgdPluginActionEnum::check_user_permission->getRouteKey(),
            'CHECK_BLUEPRINT' => MsgdPluginActionEnum::check_blueprint->getRouteKey(),
            'GET_SHARING_GROUPS' => MsgdPluginActionEnum::get_sharing_groups->getRouteKey(),
            'PROCESS_GROUPS' => MsgdPluginActionEnum::process_groups->getRouteKey(),
            'GET_BLUEPRINT_RULES_GROUPS' => MsgdPluginActionEnum::get_blueprint_rules_groups->getRouteKey(),
        ],
        'useGroupsIds' => [
            'USE_IDS' => (bool)Configure::read(
                MsgdPluginConfigEnum::user_ids->value
            ),
        ],
    ];

    $jsonFlags = JSON_HEX_TAG
        | JSON_HEX_AMP
        | JSON_HEX_APOS
        | JSON_HEX_QUOT
        | JSON_UNESCAPED_SLASHES
        | JSON_THROW_ON_ERROR;

    $urlsJson = json_encode($urlsData, $jsonFlags);

    $utilitiesConfigurationJson = json_encode(
        $utilitiesConfiguration,
        $jsonFlags
    );

    $combinedJavaScript = implode("\n", [
        'window.MsgdPlugData = Object.freeze(Object.assign('
        . '{}, window.MsgdPlugData || {}, '
        . $urlsJson
        . '));',

        'window.MsgdUtilsConfig = Object.freeze(Object.assign('
        . '{}, window.MsgdUtilsConfig || {}, '
        . $utilitiesConfigurationJson
        . '));',
    ]);

    echo $this->Html->scriptBlock(
        $combinedJavaScript,
        ['inline' => true]
    );

    echo $this->Html->script(
        MsgdPluginFileEnum::msgd_utils_js->getPath(),
        ['inline' => true]
    );
} catch (Throwable $exception) {
    MsgdLoggerUtility::logException(
        $exception,
        '[MsgdPlug CTP: utils] Error building utility JavaScript payload'
    );
}
