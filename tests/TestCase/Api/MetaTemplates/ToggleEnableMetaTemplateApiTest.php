<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\MetaTemplates;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\MetaTemplatesFixture;
use App\Test\Helper\ApiTestTrait;

class ToggleEnableMetaTemplateApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/metaTemplates/toggle/%d/enabled';

    protected $fixtures = [
        'app.Organisations',
        'app.Individuals',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
        'app.MetaTemplates'
    ];

    public function testToggleEnabledMetaTemplate(): void
    {
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $url = sprintf(self::ENDPOINT, MetaTemplatesFixture::DISABLED_TEST_ORG_META_TEMPLATE_ID);
        $this->post($url);

        $this->assertResponseOk();
        $this->assertDbRecordExists('MetaTemplates', [
            'id' =>  MetaTemplatesFixture::DISABLED_TEST_ORG_META_TEMPLATE_ID,
            'enabled' => true
        ]);
    }

    public function testToggleDisabledMetaTemplate(): void
    {
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $url = sprintf(self::ENDPOINT, MetaTemplatesFixture::ENABLED_TEST_ORG_META_TEMPLATE_ID);
        $this->post($url);

        $this->assertResponseOk();
        $this->assertDbRecordExists('MetaTemplates', [
            'id' =>  MetaTemplatesFixture::ENABLED_TEST_ORG_META_TEMPLATE_ID,
            'enabled' => false
        ]);
    }

    public function testEnableMetaTemplateNotAllowedAsRegularUser(): void
    {
        $this->setAuthToken(AuthKeysFixture::REGULAR_USER_API_KEY);

        $url = sprintf(self::ENDPOINT, MetaTemplatesFixture::DISABLED_TEST_ORG_META_TEMPLATE_ID);
        $this->post($url);

        $this->assertResponseCode(405);
        $this->assertDbRecordExists('MetaTemplates', [
            'id' =>  MetaTemplatesFixture::DISABLED_TEST_ORG_META_TEMPLATE_ID,
            'enabled' => false
        ]);
    }
}
