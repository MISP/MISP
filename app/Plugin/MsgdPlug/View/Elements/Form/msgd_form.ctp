<?php

/**
 * MsgdPlug Plugin
 *
 * @author     TETRAPI SA, Lino Pacheco
 * @license    AGPL-3.0
 */

declare(strict_types=1);

/**
 * Passes form configurations to the frontend JavaScript form module.
 *
 * @var MsgdMispActionEnum|null $action
 *
 * @package    MsgdPlug
 * @subpackage MsgdPlug.View.Elements.Form
 */

try {
    $actionInstance = $action ?? null;

    if (!$actionInstance instanceof MsgdMispActionEnum) {
        MsgdLoggerUtility::log(
            'warning',
            '[MsgdPlug CTP: form] The $action variable is missing or invalid. '
            . 'Form activeMode will be null.'
        );

        $actionInstance = null;
    } else {
        $expectedFormActions = [
            MsgdMispActionEnum::add,
            MsgdMispActionEnum::edit,
        ];

        if (!in_array($actionInstance, $expectedFormActions, true)) {
            MsgdLoggerUtility::log(
                'warning',
                sprintf(
                    '[MsgdPlug CTP: form] Unexpected action mode "%s" passed to form element. '
                    . 'Expected ADD or EDIT.',
                    $actionInstance->value
                )
            );
        }
    }

    $formConfiguration = [
        'activeMode' => $actionInstance?->value,

        'modes' => [
            'ADD' => MsgdMispActionEnum::add->value,
            'EDIT' => MsgdMispActionEnum::edit->value,
        ],

        'distLevel' => [
            'SHARING_GROUP' => MsgdMispDistributionLevelEnum::sharing_group->value,
        ],

        'messages' => [
            'LOADING_GROUPS_ERROR' => __d(
                'msgd_plug',
                'Error loading sharing groups.'
            ),

            'NETWORK_GROUPS_ERROR' => __d(
                'msgd_plug',
                'Network error while retrieving sharing groups.'
            ),

            'EMPTY_GROUPS' => __d(
                'msgd_plug',
                'No sharing groups found.'
            ),

            'EXECUTE_SUCCESS' => __d(
                'msgd_plug',
                'Operation completed successfully.'
            ),

            'VALID_SELECTION' => __d(
                'msgd_plug',
                'Your selection is valid.'
            ),

            'EXECUTE_FAILED' => __d(
                'msgd_plug',
                'Processing failed.'
            ),

            'EXECUTE_NETWORK_ERROR' => __d(
                'msgd_plug',
                'Network or server error during execution, please reload the page.'
            ),

            'STATE_CLEARED' => __d(
                'msgd_plug',
                'Cleared!'
            ),

            'STATE_PROCESSING' => __d(
                'msgd_plug',
                'Processing...'
            ),

            'STATE_SUCCESS' => __d(
                'msgd_plug',
                'Success!'
            ),

            'BTN_SELECT' => __d(
                'msgd_plug',
                'Select'
            ),

            'SHARING_GROUP' => __d(
                'msgd_plug',
                'Main Sharing Group'
            ),

            'LIMITED_ACCESS' => __d(
                'msgd_plug',
                'The combination: [ {COMBINATION} ]. Cannot be selected, '
                . 'you do not have permission to create non existing combinations, '
                . 'please contact your administrator.'
            ),
        ],
    ];

    $jsonFlags =
        JSON_HEX_TAG
        | JSON_HEX_AMP
        | JSON_HEX_APOS
        | JSON_HEX_QUOT
        | JSON_UNESCAPED_SLASHES
        | JSON_THROW_ON_ERROR;

    $configJson = json_encode(
        $formConfiguration,
        $jsonFlags
    );

    $formConfigurationScript = implode("\n", [
        'window.MsgdFormConfig = Object.freeze(Object.assign('
        . '{}, window.MsgdFormConfig || {}, '
        . $configJson
        . '));',
    ]);

    echo $this->Html->scriptBlock(
        $formConfigurationScript,
        ['inline' => true]
    );

    echo $this->Html->script(
        MsgdPluginFileEnum::msgd_form_ui_js->getPath(),
        ['inline' => true]
    );

    echo $this->Html->script(
        MsgdPluginFileEnum::msgd_form_js->getPath(),
        ['inline' => true]
    );
} catch (Throwable $exception) {
    MsgdLoggerUtility::logException(
        $exception,
        '[MsgdPlug CTP: form] Error rendering form JavaScript module configuration'
    );
}
