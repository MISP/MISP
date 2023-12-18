<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Cerebrates;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\CerebratesFixture;
use App\Test\Helper\ApiTestTrait;

class EditCerebrateApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/cerebrates/edit';

    protected $fixtures = [
        'app.Organisations',
        'app.Cerebrates',
        'app.Users',
        'app.AuthKeys'
    ];

    public function testEditCerebrate(): void
    {
        $this->skipOpenApiValidations();
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $url = sprintf('%s/%d', self::ENDPOINT, CerebratesFixture::SERVER_A_ID);
        $this->put(
            $url,
            [
                'id' => CerebratesFixture::SERVER_A_ID,
                'description' => 'new description'
            ]
        );

        $this->assertResponseOk();
        $this->assertDbRecordExists('Cerebrates', [
            'id' => CerebratesFixture::SERVER_A_ID,
            'description' => 'new description'
        ]);
    }

    public function testEditNotAllowedAsRegularUser(): void
    {
        $this->skipOpenApiValidations();
        $this->setAuthToken(AuthKeysFixture::REGULAR_USER_API_KEY);
        $url = sprintf('%s/%d', self::ENDPOINT, CerebratesFixture::SERVER_A_ID);
        $this->put(
            $url,
            [
                'id' => CerebratesFixture::SERVER_A_ID,
                'description' => 'new description'
            ]
        );
        $this->assertResponseCode(405);
        $this->assertDbRecordNotExists('Cerebrates', [
            'id' => CerebratesFixture::SERVER_A_ID,
            'description' => 'new description'
        ]);
    }
}
