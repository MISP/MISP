<?php
declare(strict_types=1);

namespace App\Test\TestCase\Model\Behavior;

use App\Model\Behavior\EventLockBehavior;
use App\Test\Fixture\EventsFixture;
use App\Test\Fixture\OrganisationsFixture;
use App\Test\Fixture\UsersFixture;
use Cake\ORM\Table;
use Cake\TestSuite\TestCase;

/**
 * App\Model\Behavior\EventLockBehavior Test Case
 */
class EventLockBehaviorTest extends TestCase
{
    /**
     * Test subject
     *
     * @var \App\Model\Behavior\EventLockBehavior
     */
    protected $EventLockBehavior;
    protected $eventId;
    protected $user;

    /**
     * setUp method
     *
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();
        $table = new Table();
        $this->EventLockBehavior = new EventLockBehavior($table);

        $this->user = [
            'id' => UsersFixture::USER_REGULAR_USER_ID,
            'org_id' => OrganisationsFixture::ORGANISATION_A_ID,
            'email' => UsersFixture::USER_REGULAR_USER_EMAIL,
        ];
        $this->eventId = EventsFixture::EVENT_1_ID;
    }

    /**
     * tearDown method
     *
     * @return void
     */
    protected function tearDown(): void
    {
        unset($this->EventLockBehavior);
        parent::tearDown();
    }

    /**
     * Test insertLockBackgroundJob method
     *
     * @return void
     * @uses \App\Model\Behavior\EventLockBehavior::insertLockBackgroundJob()
     * @uses \App\Model\Behavior\EventLockBehavior::deleteLockBackgroundJob()
     */
    public function testInsertDeleteLockBackgroundJob(): void
    {
        try {
            $jobId = 1;
            $result = $this->EventLockBehavior->insertLockBackgroundJob($this->eventId, $jobId);
            $this->assertTrue($result);
        } finally {
            $result = $this->EventLockBehavior->deleteLockBackgroundJob($this->eventId, $jobId);
            $this->assertTrue($result);
        }
    }

    /**
     * Test insertLockApi, deleteApiLock methods
     *
     * @return void
     * @uses \App\Model\Behavior\EventLockBehavior::insertLockApi()
     * @uses \App\Model\Behavior\EventLockBehavior::deleteLockApi()
     */
    public function testInsertDeleteLockApi(): void
    {
        try {
            $apiLockId = $this->EventLockBehavior->insertLockApi($this->eventId, $this->user);
            $this->assertNotEmpty($apiLockId);
        } finally {
            $output = $this->EventLockBehavior->deleteLockApi($this->eventId, $apiLockId, $this->user);
            $this->assertTrue($output);
        }
    }

    /**
     * Test insertLock, checkLock, deleteLock methods
     *
     * @return void
     * @uses \App\Model\Behavior\EventLockBehavior::insertLock()
     * @uses \App\Model\Behavior\EventLockBehavior::checkLock()
     * @uses \App\Model\Behavior\EventLockBehavior::deleteLock()
     */
    public function testInsertCheckDeleteLock(): void
    {
        try {
            $result = $this->EventLockBehavior->insertLock($this->user, $this->eventId);
            $this->assertTrue($result);

            $output = $this->EventLockBehavior->checkLock($this->user, $this->eventId);
            $this->assertNotEmpty($output);
        } finally {
            $result = $this->EventLockBehavior->deleteLock($this->eventId, $this->user);
            $this->assertTrue($result);
        }
    }
}
