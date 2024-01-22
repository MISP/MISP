<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Cerebrates;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\CerebratesFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\Http\TestSuite\HttpClientTrait;
use Cake\TestSuite\TestCase;


class PullOrgsCerebrateApiTest extends TestCase
{
    use ApiTestTrait;
    use HttpClientTrait;

    protected const ENDPOINT = '/cerebrates/pull_orgs';

    protected $fixtures = [
        'app.Organisations',
        'app.Cerebrates',
        'app.Roles',
        'app.Users',
        'app.AuthKeys'
    ];

    
    public function testPullOrgs(): void
    {
        $this->skipOpenApiValidations();
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $headers = [
            'Content-Type: application/json',
            'Connection: close',
        ];
        $response = json_encode(CerebratesFixture::CEREBRATE_ORG_LIST);
        $this->mockClientGet(
            CerebratesFixture::SERVER_A_URL.'/organisations/index',
            $this->newClientResponse(200, $headers, $response)
        );
        $url = sprintf('%s/%d', self::ENDPOINT, CerebratesFixture::SERVER_A_ID);
        $this->post($url);
        $this->assertResponseOk();
        $this->assertResponseContains(' 0 failures');
        foreach(CerebratesFixture::CEREBRATE_ORG_LIST as $org) {
            $this->assertDbRecordExists('Organisations', ['name' => $org['name'], 'uuid' => $org['uuid']]);
        }
    }

    // TODO add more test cases where existing orgs are being pulled

    public function testPullOrgsNotAllowedAsRegularUser(): void
    {
        $this->skipOpenApiValidations();
        $this->setAuthToken(AuthKeysFixture::REGULAR_USER_API_KEY);
        $url = sprintf('%s/%d', self::ENDPOINT, CerebratesFixture::SERVER_A_ID);
        $this->get($url);

        $this->assertResponseCode(405);
    }
}
