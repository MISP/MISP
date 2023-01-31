<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Individuals;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\IndividualsFixture;
use App\Test\Helper\ApiTestTrait;

class IndexIndividualsApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/individuals/index';

    protected $fixtures = [
        'app.Organisations',
        'app.Individuals',
        'app.Roles',
        'app.Users',
        'app.AuthKeys'
    ];

    public function testIndexIndividuals(): void
    {
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $this->get(self::ENDPOINT);

        $this->assertResponseOk();
        $this->assertResponseContains(sprintf('"id": %d', IndividualsFixture::INDIVIDUAL_ADMIN_ID));
    }
}
