<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\ObjectTemplates;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\ObjectTemplatesFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class DeleteObjectTemplateApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/object-templates/delete';

    protected $fixtures = [
        'app.Organisations',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
        'app.ObjectTemplates',
        'app.ObjectTemplateElements',
    ];

    public function testDeleteObjectTemplateById(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $url = sprintf('%s/%s', self::ENDPOINT, ObjectTemplatesFixture::OBJECT_TEMPLATE_1_ID);
        $this->delete($url);

        $this->assertResponseOk();
        $this->assertDbRecordNotExists('ObjectTemplates', ['id' => ObjectTemplatesFixture::OBJECT_TEMPLATE_1_ID]);
    }
}
