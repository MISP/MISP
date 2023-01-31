<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\MetaTemplates;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Helper\ApiTestTrait;

class CreateMetaTemplateApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/metaTemplates/createNewTemplate';

    public const CSIRT_META_TEMPLATE_UUID = 'faca6acc-23e0-4585-8fd8-4379e3a6250d';

    protected $fixtures = [
        'app.Organisations',
        'app.Individuals',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
        'app.MetaTemplates'
    ];

    public function testLoadMetaTemplate(): void
    {
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $url = sprintf('%s/%s', self::ENDPOINT, self::CSIRT_META_TEMPLATE_UUID);
        $this->post($url);

        $this->assertResponseOk();
        $this->assertDbRecordExists('MetaTemplates', [
            'uuid' =>  self::CSIRT_META_TEMPLATE_UUID,
        ]);
    }

    public function testLoadMetaTemplateNotAllowedAsRegularUser(): void
    {
        $this->setAuthToken(AuthKeysFixture::REGULAR_USER_API_KEY);

        $url = sprintf('%s/%s', self::ENDPOINT, self::CSIRT_META_TEMPLATE_UUID);
        $this->post($url);

        $this->assertResponseCode(405);
        $this->assertDbRecordNotExists('MetaTemplates', [
            'uuid' =>  self::CSIRT_META_TEMPLATE_UUID,
        ]);
    }
}
