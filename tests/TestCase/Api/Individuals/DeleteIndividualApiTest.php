<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Individuals;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\IndividualsFixture;
use App\Test\Helper\ApiTestTrait;

class DeleteIndividualApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/individuals/delete';

    protected $fixtures = [
        'app.Organisations',
        'app.Individuals',
        'app.Roles',
        'app.Users',
        'app.AuthKeys'
    ];

    public function testDeleteIndividual(): void
    {
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $url = sprintf('%s/%d', self::ENDPOINT, IndividualsFixture::INDIVIDUAL_A_ID);
        $this->delete($url);

        $this->assertResponseOk();
        $this->assertDbRecordNotExists('Individuals', ['id' => IndividualsFixture::INDIVIDUAL_A_ID]);
    }

    public function testDeleteIndividualNotAllowedAsRegularUser(): void
    {
        $this->setAuthToken(AuthKeysFixture::REGULAR_USER_API_KEY);
        $url = sprintf('%s/%d', self::ENDPOINT, IndividualsFixture::INDIVIDUAL_ADMIN_ID);
        $this->delete($url);

        $this->assertResponseCode(405);
        $this->assertDbRecordExists('Individuals', ['id' => IndividualsFixture::INDIVIDUAL_ADMIN_ID]);
    }
}
