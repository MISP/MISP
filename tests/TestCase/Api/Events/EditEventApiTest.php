<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Events;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\EventsFixture;
use App\Test\Fixture\OrganisationsFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;
use App\Model\Entity\Analysis;
use App\Model\Entity\Distribution;
use App\Model\Entity\ThreatLevel;

class EditEventApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/events/edit';

    protected $fixtures = [
        'app.Organisations',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
        'app.Events'
    ];

    public function testEditEvent(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $url = sprintf('%s/%s', self::ENDPOINT, EventsFixture::EVENT_1_ID);

        $this->put(
            $url,
            [
                'id' => EventsFixture::EVENT_1_ID,
                'orgc_id' => OrganisationsFixture::ORGANISATION_A_ID,
                "info" => "updated test event info",
                'distribution' => Distribution::ORGANISATION_ONLY,
                'analysis' => Analysis::COMPLETED,
                'threat_level_id' => ThreatLevel::LOW,
            ]
        );

        $this->assertResponseOk();
        $this->assertDbRecordExists(
            'Events',
            [
                'id' => EventsFixture::EVENT_1_ID,
                'info' => 'updated test event info',
                'distribution' => Distribution::ORGANISATION_ONLY,
                'analysis' => Analysis::COMPLETED,
                'threat_level_id' => ThreatLevel::LOW
            ]
        );
    }
}
