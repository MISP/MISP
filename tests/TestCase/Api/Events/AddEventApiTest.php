<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Events;

use App\Model\Entity\Analysis;
use App\Model\Entity\Distribution;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\OrganisationsFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class AddEventApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/events/add';

    protected $fixtures = [
        'app.Organisations',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
        'app.Events'
    ];

    public function testAddEvent(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $this->post(
            self::ENDPOINT,
            [
                'Event' => [
                    "orgc_id" => OrganisationsFixture::ORGANISATION_A_ID,
                    "analysis" => Analysis::INITIAL,
                    "distribution" => Distribution::ORGANISATION_ONLY,
                    "info" => "Test add event from API"
                ]
            ]
        );

        $this->assertResponseOk();
        $this->assertDbRecordExists('Events', ['info' => 'Test add event from API']);
    }
}
