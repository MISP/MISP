<?php

/**
 * MsgdPlug Plugin
 *
 * @author     TETRAPI SA, Lino Pacheco
 * @license    AGPL-3.0
 */

declare(strict_types=1);

/**
 * Plugin configs options.
 *
 * @package    MsgdPlug
 * @subpackage MsgdPlug.Lib.Enum
 */
enum MsgdPluginConfigEnum: string
{
    case enable = 'Plugin.MsgdPlug_enabled';
    case user_ids = 'Plugin.MsgdPlug_use_ids';
    case debug = 'Plugin.MsgdPlug_debug';
    case controller_whitelist = 'Plugin.MsgdPlug_controller_whitelist';
    case user_permissions_whitelist = 'Plugin.MsgdPlug_user_permissions_whitelist';
}
