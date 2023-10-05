<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\ObjectTemplates;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\ObjectTemplateElementsFixture;
use App\Test\Fixture\ObjectTemplatesFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class ViewObjectTemplateApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/object-templates/view';

    protected $fixtures = [
        'app.Organisations',
        'app.Users',
        'app.AuthKeys',
        'app.ObjectTemplates',
        'app.ObjectTemplateElements',
    ];

    public function testViewNoticelistById(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $url = sprintf('%s/%d', self::ENDPOINT, ObjectTemplatesFixture::OBJECT_TEMPLATE_1_ID);
        $this->get($url);

        $this->assertResponseOk();
        $objectTemplate = $this->getJsonResponseAsArray();

        $this->assertEquals(ObjectTemplatesFixture::OBJECT_TEMPLATE_1_ID, $objectTemplate['id']);
        $this->assertEquals(ObjectTemplatesFixture::OBJECT_TEMPLATE_1_NAME, $objectTemplate['name']);

        $this->assertArrayHasKey('ObjectTemplateElement', $objectTemplate);
        $this->assertCount(1, $objectTemplate['ObjectTemplateElement']);
        $this->assertEquals(ObjectTemplateElementsFixture::OBJECT_TEMPLATE_ELEMENT_1_ID, $objectTemplate['ObjectTemplateElement'][0]['id']);
    }
}
