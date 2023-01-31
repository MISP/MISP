<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Organisations;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\OrganisationsFixture;
use App\Test\Helper\ApiTestTrait;

class ViewOrganisationApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/organisations/view';

    protected $fixtures = [
        'app.TagsTags',
        'app.Organisations',
        'app.TagsTaggeds',
        'app.Individuals',
        'app.Roles',
        'app.Users',
        'app.AuthKeys'
    ];

    public function testViewOrganisationById(): void
    {
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $url = sprintf('%s/%d', self::ENDPOINT, OrganisationsFixture::ORGANISATION_A_ID);
        $this->get($url);

        $this->assertResponseOk();
        $this->assertResponseContains('"name": "Organisation A"');
    }
}
