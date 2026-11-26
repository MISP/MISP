<?php

/**
 * MsgdPlug Plugin
 *
 * @author     TETRAPI SA, Lino Pacheco
 * @license    AGPL-3.0
 */

declare(strict_types=1);

/**
 * Plugin Routes Configuration
 *
 * Maps RFC 3986 kebab-case public URLs to internal camelCase controller actions.
 *
 * @package    MsgdPlug
 * @subpackage MsgdPlug.Config
 */

Router::connect(
    '/msgd-plug/msgd-api/check-user-permission',
    [
        'plugin' => 'msgd_plug',
        'controller' => 'msgd_api',
        'action' => 'checkUserPermission',
    ]
);

Router::connect(
    '/msgd-plug/msgd-api/get-blueprint-rules-groups',
    [
        'plugin' => 'msgd_plug',
        'controller' => 'msgd_api',
        'action' => 'getBlueprintRulesGroups',
    ]
);

Router::connect(
    '/msgd-plug/msgd-api/get-sharing-groups',
    [
        'plugin' => 'msgd_plug',
        'controller' => 'msgd_api',
        'action' => 'getSharingGroups',
    ]
);

Router::connect(
    '/msgd-plug/msgd-api/check-blueprint',
    [
        'plugin' => 'msgd_plug',
        'controller' => 'msgd_api',
        'action' => 'checkBlueprint',
    ]
);

Router::connect(
    '/msgd-plug/msgd-api/process-groups',
    [
        'plugin' => 'msgd_plug',
        'controller' => 'msgd_api',
        'action' => 'processGroups',
    ]
);
