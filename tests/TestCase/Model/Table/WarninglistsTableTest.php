<?php
declare(strict_types=1);

namespace App\Test\TestCase\Model\Table;

use App\Model\Table\WarninglistsTable;
use App\Test\Fixture\OrganisationsFixture;
use App\Test\Fixture\UsersFixture;
use Cake\TestSuite\TestCase;

/**
 * App\Model\Table\WarninglistsTable Test Case
 */
class WarninglistsTableTest extends TestCase
{
    /**
     * Test subject
     *
     * @var \App\Model\Table\WarninglistsTable
     */
    protected $Warninglists;
    protected $user;

    /**
     * Fixtures
     *
     * @var array
     */
    protected $fixtures = [
        'app.Warninglists',
        'app.WarninglistEntries',
        'app.Users',
        'app.Organisations',
    ];

    /**
     * setUp method
     *
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();
        $config = $this->getTableLocator()->exists('Warninglists') ? [] : ['className' => WarninglistsTable::class];
        $this->Warninglists = $this->getTableLocator()->get('Warninglists', $config);

        $this->user = [
            'id' => UsersFixture::USER_REGULAR_USER_ID,
            'org_id' => OrganisationsFixture::ORGANISATION_A_ID,
            'email' => UsersFixture::USER_REGULAR_USER_EMAIL,
        ];
    }

    /**
     * tearDown method
     *
     * @return void
     */
    protected function tearDown(): void
    {
        unset($this->Warninglists);

        parent::tearDown();
    }

    /**
     * Test initialize method
     *
     * @return void
     */
    public function testInitialize(): void
    {
        $this->markTestIncomplete('Not implemented yet.');
    }

    /**
     * Test validationDefault method
     *
     * @return void
     */
    public function testValidationDefault(): void
    {
        $this->markTestIncomplete('Not implemented yet.');
    }


    public function testParseFreetext(): void
    {
        $faker = \Faker\Factory::create();
        $items = [];
        for ($i = 0; $i < 10; $i++) {
            $items[] = $faker->domainName() . " #" . $faker->sentence();
        }
        $items[] = "";    // empty to verify trim
        $items[] = " # "; // empty to verify trim
        $freetext = implode("\n", $items);
        $result = WarninglistsTable::parseFreetext($freetext);
        $this->assertEquals(count($result), 10);
    }
}
