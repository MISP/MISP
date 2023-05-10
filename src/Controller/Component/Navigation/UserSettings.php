<?php
namespace BreadcrumbNavigation;

require_once(APP . 'Controller' . DS . 'Component' . DS . 'Navigation' . DS . 'base.php'); 

class UserSettingsNavigation extends BaseNavigation
{

    public function addRoutes()
    {
        $this->bcf->addRoute('UserSettings', 'index', [
            'label' => __('User settings'),
            'url' => '/user-settings/index/',
            'icon' => 'user-cog'
        ]);
    }

    public function addLinks()
    {
        $bcf = $this->bcf;
        $request = $this->request;
        $this->bcf->addLink('UserSettings', 'index', 'Users', 'view', function ($config) use ($bcf, $request) {
            if (!empty($request->getQuery('Users_id'))) {
                $user_id = h($request->getQuery('Users_id'));
                $linkData = [
                    'label' => __('View user [{0}]', h($user_id)),
                    'url' => sprintf('/users/view/%s', h($user_id))
                ];
                return $linkData;
            }
            return null;
        });
        $this->bcf->addLink('UserSettings', 'index', 'Users', 'edit', function ($config) use ($bcf, $request) {
            if (!empty($request->getQuery('Users_id'))) {
                $user_id = h($request->getQuery('Users_id'));
                $linkData = [
                    'label' => __('Edit user [{0}]', h($user_id)),
                    'url' => sprintf('/users/edit/%s', h($user_id))
                ];
                return $linkData;
            }
            return null;
        });
        if (!empty($request->getQuery('Users_id'))) {
            $this->bcf->addSelfLink('UserSettings', 'index');
        }
        if ($this->request->getParam('controller') == 'UserSettings' && $this->request->getParam('action') == 'index') {
            if (!empty($this->request->getQuery('Users_id'))) {
                $user_id = $this->request->getQuery('Users_id');
                $this->bcf->addParent('UserSettings', 'index', 'Users', 'view', [
                    'textGetter' => [
                        'path' => 'username',
                        'varname' => 'settingsForUser',
                    ],
                    'url' => "/users/view/{$user_id}"
                ]);
            }
        }
    }
}
