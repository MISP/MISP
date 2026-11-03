<?php

/**
 * MsgdPlug Plugin
 *
 * @author     TETRAPI SA, Lino Pacheco
 * @license    AGPL-3.0
 */

declare(strict_types=1);

/**
 * MISP distribution levels.
 *
 * @package    MsgdPlug
 * @subpackage MsgdPlug.Lib.Enum
 */
enum MsgdMispDistributionLevelEnum: int
{
    case your_organization_only = 0;
    case this_community_only = 1;
    case connected_communities = 2;
    case all_communities = 3;
    case sharing_group = 4;
    case inherit = 5;
}
