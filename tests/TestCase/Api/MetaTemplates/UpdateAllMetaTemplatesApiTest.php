<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\MetaTemplates;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\MetaTemplatesFixture;
use App\Test\Helper\ApiTestTrait;
use App\Model\Table\MetaTemplatesTable;

class UpdateAllMetaTemplatesApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/metaTemplates/updateAllTemplates';

    protected $fixtures = [
        'app.Organisations',
        'app.Individuals',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
        'app.MetaTemplates',
        'app.MetaTemplateFields'
    ];

    public function testUpdateAllMetaTemplates(): void
    {
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $this->post(self::ENDPOINT);

        $this->assertResponseOk();

        $response = $this->getJsonResponseAsArray();
        $this->assertEmpty($response['update_errors']);
        $this->assertNotEmpty($response['files_processed']);
        $this->assertTrue($response['success']);

        $this->assertDbRecordExists('MetaTemplates', [
            'id' =>  3 // id 1 and 2 are loaded via MetaTemplatesFixture
        ]);
    }
}
