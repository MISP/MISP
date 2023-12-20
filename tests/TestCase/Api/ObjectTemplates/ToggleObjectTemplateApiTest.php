<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\ObjectTemplates;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\ObjectTemplatesFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class ToggleObjectTemplateApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/object-templates/activate';

    protected $fixtures = [
        'app.Organisations',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
        'app.ObjectTemplates',
        'app.ObjectTemplateElements',
    ];

    public function testActivateObjectTemplate(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        # activate
        $this->assertDbRecordExists('ObjectTemplates', ['id' => ObjectTemplatesFixture::OBJECT_TEMPLATE_2_ID, 'active' => false]);
        $this->post(self::ENDPOINT, ['id' => ObjectTemplatesFixture::OBJECT_TEMPLATE_2_ID]);
        $this->assertResponseOk();
        $this->assertDbRecordExists('ObjectTemplates', ['id' => ObjectTemplatesFixture::OBJECT_TEMPLATE_2_ID, 'active' => true]);
    }

    public function testDisableObjectTemplate(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        # disable
        $this->assertDbRecordExists('ObjectTemplates', ['id' => ObjectTemplatesFixture::OBJECT_TEMPLATE_1_ID, 'active' => true]);
        $this->post(self::ENDPOINT, ['id' => ObjectTemplatesFixture::OBJECT_TEMPLATE_1_ID]);
        $this->assertResponseOk();
        $this->assertDbRecordExists('ObjectTemplates', ['id' => ObjectTemplatesFixture::OBJECT_TEMPLATE_1_ID, 'active' => false]);
    }
}
