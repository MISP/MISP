<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Cerebrates;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\CerebratesFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\Http\TestSuite\HttpClientTrait;
use Cake\TestSuite\TestCase;


class PreviewSharingGroupsCerebrateApiTest extends TestCase
{
    use ApiTestTrait;
    use HttpClientTrait;

    protected const ENDPOINT = '/cerebrates/preview_sharing_groups';

    protected $fixtures = [
        'app.Organisations',
        'app.Cerebrates',
        'app.Roles',
        'app.Users',
        'app.AuthKeys'
    ];

    
    public function testPreviewSharingGroups(): void
    {
        $this->skipOpenApiValidations();
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $headers = [
            'Content-Type: application/json',
            'Connection: close',
        ];
        $response = json_encode(CerebratesFixture::CEREBRATE_SG_LIST);
        $this->mockClientGet(
            CerebratesFixture::SERVER_A_URL.'/sharingGroups/index',
            $this->newClientResponse(200, $headers, $response)
        );
        $url = sprintf('%s/%d', self::ENDPOINT, CerebratesFixture::SERVER_A_ID);
        $this->get($url);
        $this->assertResponseOk();
        $this->assertResponseContains('"name": "SG_cerebrate_1"');
    }

    public function testPreviewSharingGroupsNotAllowedAsRegularUser(): void
    {
        $this->skipOpenApiValidations();
        $this->setAuthToken(AuthKeysFixture::REGULAR_USER_API_KEY);
        $url = sprintf('%s/%d', self::ENDPOINT, CerebratesFixture::SERVER_A_ID);
        $this->get($url);

        $this->assertResponseCode(405);
    }
}
