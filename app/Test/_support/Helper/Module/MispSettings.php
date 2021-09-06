<?php

declare(strict_types=1);

namespace Helper\Module;

final class MispSettings extends \Codeception\Module implements \Codeception\Lib\Interfaces\DependsOnModule
{
    /** @var Api */
    private $apiModule;

    public function _depends()
    {
        return [
            'Helper\Module\Api' => 'Api is a mandatory dependency of MispSettings',
        ];
    }

    public function _inject(Api $apiModule): void
    {
        $this->apiModule = $apiModule;
    }

    public function haveMispSetting(string $setting, string $value): void
    {
        $this->apiModule->sendPost(
            sprintf('/servers/serverSettingsEdit/%s/null/1', $setting), // forceSave
            [
                'value' => $value
            ]
        );

        $this->apiModule->seeResponseCodeIs(200);
        $this->apiModule->seeResponseContainsJson(
            [
                'saved' => true,
                'success' => true,
                'name' => 'Field updated',
                'message' => 'Field updated',
                'url' => '/servers/serverSettingsEdit',
            ]
        );
    }
}
