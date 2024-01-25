<?php
declare(strict_types=1);

namespace App\Test\TestCase\Api\Cerebrates;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\CerebratesFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\Http\TestSuite\HttpClientTrait;
use Cake\TestSuite\TestCase;

class DownloadOrgCerebrateApiTest extends TestCase
{
    use ApiTestTrait;
    use HttpClientTrait;

    protected const ENDPOINT = '/cerebrates/download_org';

    protected $fixtures = [
        'app.Organisations',
        'app.Cerebrates',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
    ];

    public function testDownloadOrg(): void
    {
        $this->skipOpenApiValidations();
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $headers = [
            'Content-Type: application/json',
            'Connection: close',
        ];
        $response = json_encode(CerebratesFixture::CEREBRATE_ORG_LIST[0]);
        $this->mockClientGet(
            CerebratesFixture::SERVER_A_URL . '/organisations/view/' . CerebratesFixture::CEREBRATE_ORG_LIST[0]['id'],
            $this->newClientResponse(200, $headers, $response)
        );
        $url = sprintf('%s/%d/%d', self::ENDPOINT, CerebratesFixture::SERVER_A_ID, CerebratesFixture::CEREBRATE_ORG_LIST[0]['id']);
        $this->post($url);
        $this->assertResponseOk();
        $this->assertResponseContains('"name": "' . CerebratesFixture::CEREBRATE_ORG_LIST[0]['name'] . '"');
        $this->assertDbRecordExists('Organisations', ['name' => CerebratesFixture::CEREBRATE_ORG_LIST[0]['name']]);
    }

    // TODO add a test to add new data to an existing organisation
    // public function testDownloadOrgUpdateExisting(): void
    // {

    // }

    public function testDownloadOrgNotAllowedAsRegularUser(): void
    {
        $this->skipOpenApiValidations();
        $this->setAuthToken(AuthKeysFixture::REGULAR_USER_API_KEY);
        $url = sprintf('%s/%d/%d', self::ENDPOINT, CerebratesFixture::SERVER_A_ID, CerebratesFixture::CEREBRATE_ORG_LIST[0]['id']);
        $this->post($url);

        $this->assertResponseCode(405);
    }
}
