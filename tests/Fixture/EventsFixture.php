<?php

declare(strict_types=1);

namespace App\Test\Fixture;

use App\Model\Entity\Analysis;
use App\Model\Entity\Distribution;
use App\Model\Entity\ThreatLevel;
use Cake\TestSuite\Fixture\TestFixture;

class EventsFixture extends TestFixture
{
    public $connection = 'test';

    public const EVENT_1_ID = 1000;
    public const EVENT_1_UUID = '02a5f2e5-3c6c-4d40-b973-de465fd2f370';

    public const EVENT_2_ID = 2000;
    public const EVENT_2_UUID = '087f13f9-f15f-4f53-b141-b4a9165cc175';

    public function init(): void
    {
        $this->records = [
            [
                'id' => self::EVENT_1_ID,
                'info' => 'Event 1',
                'org_id' => OrganisationsFixture::ORGANISATION_A_ID,
                'orgc_id' => OrganisationsFixture::ORGANISATION_A_ID,
                'user_id' => UsersFixture::USER_ADMIN_ID,
                'distribution' => Distribution::ALL_COMMUNITIES,
                'analysis' => Analysis::INITIAL,
                'threat_level_id' => ThreatLevel::HIGH,
                'date' => '2021-01-01 00:00:00',
                'published' => 0,
                'uuid' => self::EVENT_1_UUID,
                'attribute_count' => 1,
                'sharing_group_id' => 0,
            ],
            [
                'id' => self::EVENT_2_ID,
                'info' => 'Event 2',
                'org_id' => OrganisationsFixture::ORGANISATION_A_ID,
                'orgc_id' => OrganisationsFixture::ORGANISATION_A_ID,
                'user_id' => UsersFixture::USER_ADMIN_ID,
                'distribution' => Distribution::ALL_COMMUNITIES,
                'analysis' => Analysis::INITIAL,
                'threat_level_id' => ThreatLevel::HIGH,
                'date' => '2021-01-01 00:00:00',
                'published' => 1,
                'uuid' => self::EVENT_2_UUID,
                'attribute_count' => 0,
                'sharing_group_id' => 0,
            ]
        ];
        parent::init();
    }
}
