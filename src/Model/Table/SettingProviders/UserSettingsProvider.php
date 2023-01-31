<?php

namespace App\Settings\SettingsProvider;

use Cake\ORM\TableRegistry;

require_once(APP . 'Model' . DS . 'Table' . DS . 'SettingProviders' . DS . 'BaseSettingsProvider.php');

use App\Settings\SettingsProvider\BaseSettingsProvider;

class UserSettingsProvider extends BaseSettingsProvider
{
    protected function generateSettingsConfiguration()
    {
        return [
            __('Appearance') => [
                __('User Interface') => [
                    'ui.bsTheme' => [
                        'description' => 'The Bootstrap theme to use for the application',
                        'default' => 'default',
                        'name' => 'UI Theme',
                        'options' => (function () {
                            $instanceTable = TableRegistry::getTableLocator()->get('Instance');
                            $themes = $instanceTable->getAvailableThemes();
                            return array_combine($themes, $themes);
                        })(),
                        'severity' => 'info',
                        'type' => 'select'
                    ],
                    'ui.sidebar.expanded' => [
                        'name' => __('Sidebar expanded'),
                        'type' => 'boolean',
                        'description' => __('Should the left navigation sidebar expanded and locked.'),
                        'default' => false,
                        'severity' => 'info',
                    ],
                    'ui.sidebar.include_bookmarks' => [
                        'name' => __('Include bookmarks in the sidebar'),
                        'type' => 'boolean',
                        'description' => __('Should bookmarks links included in the sidebar.'),
                        'default' => false,
                        'severity' => 'info',
                    ],
                ]
            ],
            __('Account Security') => [
            ]
        ];
    }
}