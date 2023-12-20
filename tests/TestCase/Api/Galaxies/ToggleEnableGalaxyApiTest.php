<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Galaxies;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\GalaxiesFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class ToggleEnableGalaxyApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/galaxies/toggle';

    protected $fixtures = [
        'app.Organisations',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
        'app.Galaxies'
    ];

    public function testToggleEnableGalaxy(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $url = sprintf('%s/%d', self::ENDPOINT, GalaxiesFixture::GALAXY_1_ID);

        # enable
        $this->assertDbRecordExists('Galaxies', ['id' => GalaxiesFixture::GALAXY_1_ID, 'enabled' => false]);
        $this->post($url);
        $this->assertResponseOk();
        $this->assertResponseContains('"message": "Galaxy enabled"');
        $this->assertDbRecordExists('Galaxies', ['id' => GalaxiesFixture::GALAXY_1_ID, 'enabled' => true]);
    }

    public function testToggleDisableGalaxy(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $url = sprintf('%s/%d', self::ENDPOINT, GalaxiesFixture::GALAXY_2_ID);

        $this->assertDbRecordExists('Galaxies', ['id' => GalaxiesFixture::GALAXY_2_ID, 'enabled' => true]);
        $this->post($url);
        $this->assertResponseOk();
        $this->assertResponseContains('"message": "Galaxy disabled"');
        $this->assertDbRecordExists('Galaxies', ['id' => GalaxiesFixture::GALAXY_2_ID, 'enabled' => false]);
    }
}
