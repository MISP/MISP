<?php
/**
 * Regression tests for Sighting::restSearch org_id filtering.
 *
 * The regular PHPUnit suite does not bootstrap CakePHP or a database. Exercise
 * the actual Sighting model's condition builder with minimal framework doubles;
 * database/ACL output is additionally covered by the staging integration run.
 *
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 */
require_once __DIR__ . '/../Vendor/autoload.php';

use PHPUnit\Framework\TestCase;

/**
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 */
class SightingRestSearchOrgIdTest extends TestCase
{
    protected function setUp(): void
    {
        require_once __DIR__ . '/SightingOrgIdTestFixture.php';
    }

    private function conditions($filter)
    {
        $model = new SightingOrgFilterTestModel();
        $user = ['org_id' => 9101, 'Role' => ['perm_site_admin' => true]];
        $model->restSearch($user, 'json', ['last' => '365d', 'org_id' => $filter]);
        return $model->capturedConditions;
    }

    public function testNumericAndUuidIdentifiers()
    {
        $this->assertSame([9101], $this->conditions(9101)['Sighting.org_id']);
        $this->assertSame([9102], $this->conditions('9102')['Sighting.org_id']);
        $this->assertSame([9101], $this->conditions('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa')['Sighting.org_id']);
        $this->assertSame([9101, 9102], $this->conditions([
            'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 9102
        ])['Sighting.org_id']);
    }

    public function testNegationPreservesExistingMeaning()
    {
        $this->assertSame([9101], $this->conditions('!9101')['Sighting.org_id NOT IN']);
        $this->assertSame([9101], $this->conditions('!aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa')['Sighting.org_id NOT IN']);
        $conditions = $this->conditions(['bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', '!9101']);
        $this->assertSame([9102], $conditions['Sighting.org_id']);
        $this->assertSame([9101], $conditions['Sighting.org_id NOT IN']);
    }

    public function testUnknownOrgDoesNotReusePreviousValueOrWidenQuery()
    {
        $unknown = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
        $this->assertSame([-1], $this->conditions($unknown)['Sighting.org_id']);
        $this->assertSame([9101, -1], $this->conditions([
            'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', $unknown
        ])['Sighting.org_id']);
        $conditions = $this->conditions(['aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', '!' . $unknown]);
        $this->assertSame([9101], $conditions['Sighting.org_id']);
        $this->assertArrayNotHasKey('Sighting.org_id NOT IN', $conditions);
        $this->assertArrayNotHasKey('Sighting.org_id NOT IN', $this->conditions('!' . $unknown));
    }

    public function testNonIdentifierAndEmptyStringDoNotLeakPreviousOrg()
    {
        $conditions = $this->conditions(['aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', '', []]);
        $this->assertSame([9101, -1, -1], $conditions['Sighting.org_id']);
        $this->assertArrayNotHasKey('Sighting.org_id', $this->conditions('!'));
    }
}
