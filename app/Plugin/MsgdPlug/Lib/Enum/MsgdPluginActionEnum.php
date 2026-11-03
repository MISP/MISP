<?php

/**
 * MsgdPlug Plugin
 *
 * @author     TETRAPI SA, Lino Pacheco
 * @license    AGPL-3.0
 */

declare(strict_types=1);

/**
 * Supported plugin actions.
 *
 * @package    MsgdPlug
 * @subpackage MsgdPlug.Lib.Enum
 */
enum MsgdPluginActionEnum: string
{
    case process_groups = 'processGroups';
    case get_sharing_groups = 'getSharingGroups';
    case check_blueprint = 'checkBlueprint';
    case get_blueprint_rules_groups = 'getBlueprintRulesGroups';
    case check_user_permission = 'checkUserPermission';

    /**
     * Generates the route payload key used for frontend URL passing.
     *
     * @return string
     */
    public function getRouteKey(): string
    {
        return $this->value . 'Url';
    }
}
