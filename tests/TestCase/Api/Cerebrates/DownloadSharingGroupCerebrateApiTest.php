<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Cerebrates;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\CerebratesFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\Http\TestSuite\HttpClientTrait;
use Cake\TestSuite\TestCase;


class DownloadSharingGroupCerebrateApiTest extends TestCase
{
    use ApiTestTrait;
    use HttpClientTrait;

    protected const ENDPOINT = '/cerebrates/download_sg';

    protected $fixtures = [
        'app.Organisations',
        'app.Cerebrates',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
        'app.SharingGroups'
    ];

    
    public function testDownloadSharingGroup(): void
    {
        $this->skipOpenApiValidations();
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $headers = [
            'Content-Type: application/json',
            'Connection: close',
        ];
        $response = json_encode(CerebratesFixture::CEREBRATE_SG_LIST[0]);
        $this->mockClientGet(
            CerebratesFixture::SERVER_A_URL.'/sharingGroups/view/'.CerebratesFixture::CEREBRATE_SG_LIST[0]['id'],
            $this->newClientResponse(200, $headers, $response)
        );
        $url = sprintf('%s/%d/%d', self::ENDPOINT, CerebratesFixture::SERVER_A_ID, CerebratesFixture::CEREBRATE_SG_LIST[0]['id']);
        $this->post($url);
        $this->assertResponseOk();
        $this->assertResponseContains('"name": "'.CerebratesFixture::CEREBRATE_SG_LIST[0]['name'].'"');
        $this->assertDbRecordExists('SharingGroups', ['name' => CerebratesFixture::CEREBRATE_SG_LIST[0]['name'], 'uuid' => CerebratesFixture::CEREBRATE_SG_LIST[0]['uuid']]);

    }

        // TODO add multiple tests to add new data to an existing SG (new metadata, new existing org, new new org, ...)
    // public function testDownloadSharingGroupUpdateExisting(): void
    // {
        
    // }

    public function testDownloadSharingGroupNotAllowedAsRegularUser(): void
    {
        $this->skipOpenApiValidations();
        $this->setAuthToken(AuthKeysFixture::REGULAR_USER_API_KEY);
        $url = sprintf('%s/%d', self::ENDPOINT, CerebratesFixture::SERVER_A_ID);
        $this->get($url);

        $this->assertResponseCode(405);
    }
}
