<?php

/**
 * MsgdPlug Plugin
 *
 * @author     TETRAPI SA, Lino Pacheco
 * @license    AGPL-3.0
 */

declare(strict_types=1);

/**
 * Status types.
 *
 * @package    MsgdPlug
 * @subpackage MsgdPlug.Lib.Enum
 */
enum MsgdPluginStatusEnum: string
{
    case success = 'success';
    case error = 'error';
    case info = 'info';
    case warning = 'warning';
}
