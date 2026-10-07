<?php

/**
 * MsgdPlug Plugin
 *
 * @author     TETRAPI SA, Lino Pacheco
 * @license    AGPL-3.0
 */

declare(strict_types=1);

/**
 * Plugin utility file paths.
 *
 * @package    MsgdPlug
 * @subpackage MsgdPlug.Lib.Enum
 */
enum MsgdPluginFileEnum: string
{
    case msgd_injector_php = 'MsgdInjector';
    case msgd_style_css = 'msgd_style';
    case msgd_view_js = 'msgd_view';
    case msgd_form_js = 'msgd_form';
    case msgd_form_ui_js = 'msgd_form_ui';
    case msgd_utils_js = 'msgd_utils';
    case msgd_templates_ctp = 'Common/msgd_templates';
    case msgd_utils_ctp = 'Common/msgd_utils';
    case msgd_form_ctp = 'Form/msgd_form';
    case msgd_view_ctp = 'View/msgd_view';

    /**
     * Returns the full CakePHP file path.
     *
     * @return string
     */
    public function getPath(): string
    {
        return 'MsgdPlug.' . $this->value;
    }
}
