<?php

namespace App\Model\Table\SettingProviders;

use Cake\ORM\TableRegistry;

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
            __('Account Security') => [],
            __('Rest Search') => [
                'default_restsearch_parameters' => [
                    'name' => __('Default restSearch parameters'),
                    'type' => 'boolean',
                    'description' => __('Default restSearch parameters.'),
                    'default' => [],
                    'severity' => 'info',
                ]
            ]
        ];
    }
}
