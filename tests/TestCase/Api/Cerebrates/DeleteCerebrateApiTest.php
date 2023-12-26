<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Cerebrates;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\CerebratesFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class DeleteCerebrateApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/cerebrates/delete';

    protected $fixtures = [
        'app.Organisations',
        'app.Cerebrates',
        'app.Roles',
        'app.Users',
        'app.AuthKeys'
    ];

    public function testDeleteCerebrate(): void
    {
        $this->skipOpenApiValidations();
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $url = sprintf('%s/%d', self::ENDPOINT, CerebratesFixture::SERVER_A_ID);
        $this->delete($url);

        $this->assertResponseOk();
        $this->assertDbRecordNotExists('Cerebrates', ['id' => CerebratesFixture::SERVER_A_ID]);
    }

    public function testDeleteCerebrateNotAllowedAsRegularUser(): void
    {
        $this->skipOpenApiValidations();
        $this->setAuthToken(AuthKeysFixture::REGULAR_USER_API_KEY);
        $url = sprintf('%s/%d', self::ENDPOINT, CerebratesFixture::SERVER_A_ID);
        $this->delete($url);

        $this->assertResponseCode(405);
        $this->assertDbRecordExists('Cerebrates', ['id' => CerebratesFixture::SERVER_A_ID]);
    }
}
