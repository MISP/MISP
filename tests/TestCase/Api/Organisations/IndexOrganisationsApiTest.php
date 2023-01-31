<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Organisations;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\OrganisationsFixture;
use App\Test\Helper\ApiTestTrait;

class IndexOrganisationApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/organisations/index';

    protected $fixtures = [
        'app.Organisations',
        'app.Individuals',
        'app.Roles',
        'app.Users',
        'app.AuthKeys'
    ];

    public function testIndexOrganisations(): void
    {
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $this->get(self::ENDPOINT);

        $this->assertResponseOk();
        $this->assertResponseContains(sprintf('"id": %d', OrganisationsFixture::ORGANISATION_A_ID));
        $this->assertResponseContains(sprintf('"id": %d', OrganisationsFixture::ORGANISATION_B_ID));
    }
}
