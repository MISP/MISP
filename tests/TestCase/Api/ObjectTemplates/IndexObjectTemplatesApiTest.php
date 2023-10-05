<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\ObjectTemplates;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\ObjectTemplatesFixture;
use App\Test\Helper\ApiTestTrait;

class IndexObjectTemplatesApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/object-templates/index';

    protected $fixtures = [
        'app.Organisations',
        'app.Users',
        'app.AuthKeys',
        'app.ObjectTemplates',
        'app.ObjectTemplateElements',
    ];

    public function testIndexObjectTemplates(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $this->get(self::ENDPOINT);

        $this->assertResponseOk();
        $this->assertResponseContains(sprintf('"name": "%s"', ObjectTemplatesFixture::OBJECT_TEMPLATE_1_NAME));
    }
}
