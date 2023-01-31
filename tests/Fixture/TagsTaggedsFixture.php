<?php

declare(strict_types=1);

namespace App\Test\Fixture;

use Cake\TestSuite\Fixture\TestFixture;

class TagsTaggedsFixture extends TestFixture
{
    public $connection = 'test';
    public $table = 'tags_tagged';

    public const TAG_RED_ID = 1;
    public const TAG_GREEN_ID = 2;
    public const TAG_BLUE_ID = 3;

    public function init(): void
    {
        $faker = \Faker\Factory::create();

        $this->records = [
            [
                'tag_id' => TagsTagsFixture::TAG_ORG_A_ID,
                'fk_id' => OrganisationsFixture::ORGANISATION_A_ID,
                'fk_model' => 'Organisations',
                'created' => $faker->dateTime()->getTimestamp(),
                'modified' => $faker->dateTime()->getTimestamp()
            ],
            [
                'tag_id' => TagsTagsFixture::TAG_ORG_B_ID,
                'fk_id' => OrganisationsFixture::ORGANISATION_B_ID,
                'fk_model' => 'Organisations',
                'created' => $faker->dateTime()->getTimestamp(),
                'modified' => $faker->dateTime()->getTimestamp()
            ],
        ];
        parent::init();
    }
}
