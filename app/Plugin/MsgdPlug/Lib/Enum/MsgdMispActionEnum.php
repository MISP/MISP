<?php

/**
 * MsgdPlug Plugin
 *
 * @author     TETRAPI SA, Lino Pacheco
 * @license    AGPL-3.0
 */

declare(strict_types=1);

/**
 * Supported MISP controller actions.
 *
 * @package    MsgdPlug
 * @subpackage MsgdPlug.Lib.Enum
 */
enum MsgdMispActionEnum: string
{
    case add = 'add';
    case edit = 'edit';
    case view = 'view';
    case index = 'index';

    /**
     * Safely converts an action string to its matching enum case.
     *
     * @param string|null $value
     *
     * @return self|null
     */
    public static function tryFromLower(?string $value): ?self
    {
        if ($value === null) {
            return null;
        }

        return self::tryFrom(strtolower(MsgdSanitizerUtility::sanitizeString($value)));
    }

    /**
     * Returns the view element associated with this action.
     *
     * @return MsgdPluginFileEnum
     */
    public function getActionElement(): MsgdPluginFileEnum
    {
        return match ($this) {
            self::add, self::edit => MsgdPluginFileEnum::msgd_form_ctp,
            self::view, self::index => MsgdPluginFileEnum::msgd_view_ctp,
        };
    }

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
