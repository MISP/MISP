<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Individuals;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\IndividualsFixture;
use App\Test\Helper\ApiTestTrait;

class ViewIndividualApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/individuals/view';

    protected $fixtures = [
        'app.Organisations',
        'app.Individuals',
        'app.Roles',
        'app.Users',
        'app.AuthKeys'
    ];

    public function testViewIndividualById(): void
    {
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $url = sprintf('%s/%d', self::ENDPOINT, IndividualsFixture::INDIVIDUAL_ADMIN_ID);
        $this->get($url);

        $this->assertResponseOk();
        $this->assertResponseContains(sprintf('"id": %d', IndividualsFixture::INDIVIDUAL_ADMIN_ID));
    }
}
