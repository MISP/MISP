<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\MetaTemplates;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\MetaTemplatesFixture;
use App\Test\Helper\ApiTestTrait;
use App\Model\Table\MetaTemplatesTable;

class UpdateMetaTemplateByIdApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/metaTemplates/update/%d';

    protected $fixtures = [
        'app.Organisations',
        'app.Individuals',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
        'app.MetaTemplates',
        'app.MetaTemplateFields'
    ];

    public function testUpdateMetaTemplateById(): void
    {
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        // Dump MetaTemplate json file to disk 
        file_put_contents(
            ROOT . '/libraries/default/meta_fields/test.json',
            json_encode(MetaTemplatesFixture::ENABLED_TEST_ORG_META_TEMPLATE_SPEC)
        );

        $url = sprintf(self::ENDPOINT, MetaTemplatesFixture::ENABLED_TEST_ORG_META_TEMPLATE_ID);
        $this->post($url, [
            'update_strategy' =>  MetaTemplatesTable::UPDATE_STRATEGY_CREATE_NEW
        ]);

        $this->assertResponseOk();

        $response = $this->getJsonResponseAsArray();
        $this->assertEmpty($response['update_errors']);
        $this->assertNotEmpty($response['files_processed']);
        $this->assertTrue($response['success']);

        $this->assertDbRecordExists('MetaTemplateFields', [
            'field' =>  'test_field_2'
        ]);

        // Delete MetaTemplate json file from disk 
        unlink(ROOT . '/libraries/default/meta_fields/test.json');
    }
}
