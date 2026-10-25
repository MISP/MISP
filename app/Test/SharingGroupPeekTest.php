<?php
if (!function_exists('__')) {
    function __($singular, $args = null)
    {
        $arguments = func_get_args();
        return count($arguments) > 1 ? vsprintf($singular, array_slice($arguments, 1)) : $singular;
    }
}
if (!function_exists('__n')) {
    function __n($singular, $plural, $count, $args = null)
    {
        $arguments = func_get_args();
        return vsprintf($count == 1 ? $singular : $plural, array_slice($arguments, 3));
    }
}
require_once __DIR__ . '/../Lib/Tools/SharingGroupPeek.php';

use PHPUnit\Framework\TestCase;

class SharingGroupPeekTest extends TestCase
{
    private function sg(array $group = [], array $servers = [])
    {
        return [
            'SharingGroup' => $group + [
                'id' => '33', 'name' => 'CIRCL + ORG_6', 'description' => '', 'releasability' => '',
                'org_id' => '9', 'active' => true, 'local' => true, 'roaming' => false,
            ],
            'Organisation' => ['id' => '9', 'name' => 'CIRCL', 'uuid' => 'u-9'],
            'SharingGroupServer' => $servers,
        ];
    }

    private function member($id, $name, $extend = false)
    {
        return [
            'SharingGroupOrg' => ['org_id' => (string)$id, 'extend' => $extend],
            'Organisation' => ['id' => (string)$id, 'name' => $name, 'uuid' => 'u-' . $id],
        ];
    }

    public function testMembersListOwnerThenReaderThenByName(): void
    {
        $rows = [
            $this->member(28, 'ORG_6'),
            $this->member(9, 'CIRCL', true),
            $this->member(1, 'admin'),
            $this->member(4, 'beta'),
            $this->member(9, 'CIRCL', true),
        ];
        $peek = SharingGroupPeek::build($this->sg(), $rows, 4, 4);

        $this->assertSame(['CIRCL', 'beta', 'admin', 'ORG_6'], array_column($peek['members'], 'name'));
        $this->assertTrue($peek['members'][0]['owner']);
        $this->assertTrue($peek['members'][0]['extend']);
        $this->assertTrue($peek['members'][1]['you']);
        $this->assertSame(0, $peek['more']);
        $this->assertSame(33, $peek['id']);
    }

    public function testMoreCountsTheMembersNotListed(): void
    {
        $peek = SharingGroupPeek::build($this->sg(), [$this->member(9, 'CIRCL')], 30, 1);
        $this->assertSame(29, $peek['more']);
    }

    public function testHiddenMembersKeepOnlyTheCount(): void
    {
        $peek = SharingGroupPeek::build($this->sg(['roaming' => true]), null, 12, 1);
        $this->assertNull($peek['members']);
        $this->assertNull($peek['reach']);
        $this->assertSame(12, $peek['member_count']);
    }

    public function testReach(): void
    {
        $roaming = SharingGroupPeek::build($this->sg(['roaming' => true]), [], 0, 1);
        $this->assertSame('Roaming', $roaming['reach']['mode']);
        $this->assertStringStartsWith('Travels', $roaming['reach']['text']);

        $pushed = SharingGroupPeek::build($this->sg([], [
            ['server_id' => '0', 'all_orgs' => true],
            ['server_id' => '3', 'all_orgs' => false],
        ]), [], 0, 1);
        $this->assertSame(['mode' => null, 'text' => 'Pushed to 1 other instance.'], $pushed['reach']);
        $this->assertTrue($pushed['everyone']);

        $local = SharingGroupPeek::build($this->sg([], [['server_id' => '0', 'all_orgs' => false]]), [], 0, 1);
        $this->assertSame(['mode' => null, 'text' => 'Stays on this instance.'], $local['reach']);
        $this->assertFalse($local['everyone']);
    }

    public function testNotesSkipWhatRepeatsTheName(): void
    {
        $same = SharingGroupPeek::build($this->sg(['releasability' => 'circl + org_6 ', 'description' => 'CIRCL + ORG_6']), [], 0, 1);
        $this->assertSame([], $same['notes']);

        $peek = SharingGroupPeek::build($this->sg([
            'releasability' => 'Members only',
            'description' => 'Members only',
        ]), [], 0, 1);
        $this->assertSame([['label' => 'Releasable to', 'text' => 'Members only']], $peek['notes']);
    }

    public function testPillsMarkOnlyTheExceptions(): void
    {
        $this->assertSame([], SharingGroupPeek::build($this->sg(), [], 0, 1)['pills']);
        $pills = SharingGroupPeek::build($this->sg(['active' => false, 'local' => false]), [], 0, 1)['pills'];
        $this->assertSame(['Inactive', 'Received through sync'], array_column($pills, 'label'));
        $this->assertTrue($pills[0]['warn']);
    }
}
