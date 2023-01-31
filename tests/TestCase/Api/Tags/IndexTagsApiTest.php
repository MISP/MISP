<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Tags;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Helper\ApiTestTrait;

class IndexTagsApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/tags/index';

    protected $fixtures = [
        'app.TagsTags',
        'app.Individuals',
        'app.Roles',
        'app.Users',
        'app.AuthKeys'
    ];

    public function testIndexTags(): void
    {
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $this->get(self::ENDPOINT);


        $this->assertResponseOk();
        $this->assertResponseContains('"name": "red"');
        $this->assertResponseContains('"name": "green"');
        $this->assertResponseContains('"name": "blue"');
    }
}
