<?php

declare(strict_types=1);

namespace App\Test\Fixture;

use Cake\TestSuite\Fixture\TestFixture;

class TagsTagsFixture extends TestFixture
{
    public $connection = 'test';

    public const TAG_RED_ID = 1;
    public const TAG_GREEN_ID = 2;
    public const TAG_BLUE_ID = 3;
    public const TAG_ORG_A_ID = 4;
    public const TAG_ORG_B_ID = 5;

    public function init(): void
    {
        $faker = \Faker\Factory::create();

        $this->records = [
            [
                'id' => self::TAG_RED_ID,
                'name' => 'red',
                'namespace' => null,
                'predicate' => null,
                'value' => null,
                'colour' => 'FF0000',
                'counter' => 0,
                'text_colour' => 'red',
                'created' => $faker->dateTime()->getTimestamp(),
                'modified' => $faker->dateTime()->getTimestamp()
            ],
            [
                'id' => self::TAG_GREEN_ID,
                'name' => 'green',
                'namespace' => null,
                'predicate' => null,
                'value' => null,
                'colour' => '00FF00',
                'counter' => 0,
                'text_colour' => 'green',
                'created' => $faker->dateTime()->getTimestamp(),
                'modified' => $faker->dateTime()->getTimestamp()
            ],
            [
                'id' => self::TAG_BLUE_ID,
                'name' => 'blue',
                'namespace' => null,
                'predicate' => null,
                'value' => null,
                'colour' => '0000FF',
                'counter' => 0,
                'text_colour' => 'blue',
                'created' => $faker->dateTime()->getTimestamp(),
                'modified' => $faker->dateTime()->getTimestamp()
            ],
            [
                'id' => self::TAG_ORG_A_ID,
                'name' => 'org-a',
                'namespace' => null,
                'predicate' => null,
                'value' => null,
                'colour' => '000000',
                'counter' => 0,
                'text_colour' => 'black',
                'created' => $faker->dateTime()->getTimestamp(),
                'modified' => $faker->dateTime()->getTimestamp()
            ],
            [
                'id' => self::TAG_ORG_B_ID,
                'name' => 'org-b',
                'namespace' => null,
                'predicate' => null,
                'value' => null,
                'colour' => '000000',
                'counter' => 0,
                'text_colour' => 'black',
                'created' => $faker->dateTime()->getTimestamp(),
                'modified' => $faker->dateTime()->getTimestamp()
            ]
        ];
        parent::init();
    }
}
