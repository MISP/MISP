<?php
/**
 * CLICommonTrait write-guard and pagination unit tests.
 *
 * Pure — no DB, no CakePHP bootstrap. The trait is used by a small
 * harness class that exposes the private helpers.
 *
 * __canWriteEntity() is the single gate in front of the shell's add,
 * edit and delete commands and of the inline detail editor. It mirrors
 * the web ACL: site admins pass everything, `adminOnly` and
 * `writeAdminOnly` entities refuse everyone else, `writePerms` names the
 * role flag an operation needs (tags: perm_tag_editor to add, site admin
 * to edit or delete), and an entity with none of these is open, subject
 * to the per-record checks its own handlers perform.
 *
 * __normalisePagination() keeps `limit=0`, a negative or a non-numeric
 * limit from making DboSource drop the LIMIT clause and return the
 * whole table, and caps the page size.
 */

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../Console/Command/CLIShell/cli_common.php';

class CLIShellWriteGuardsHarness
{
    use CLICommonTrait;

    public $__user = [];
    public $__entityConfig = [];
    public $__perPage = 20;
    public $__maxPerPage = 1000;
    public $errors = [];

    public function err($message = null, $newlines = 1)
    {
        $this->errors[] = $message;
    }

    public function canWrite($entity, $op)
    {
        return $this->__canWriteEntity($entity, $op);
    }

    public function deny($entity, $op)
    {
        $this->__denyWrite($entity, $op);
    }

    public function paginate(array $filters)
    {
        return $this->__normalisePagination($filters);
    }
}

class CLIShellWriteGuardsTest extends TestCase
{
    /** @var CLIShellWriteGuardsHarness */
    private $shell;

    protected function setUp(): void
    {
        $this->shell = new CLIShellWriteGuardsHarness();
        $this->shell->__entityConfig = [
            'event' => ['model' => 'Event'],
            'tag' => [
                'model' => 'Tag',
                'writePerms' => [
                    'add' => 'perm_tag_editor',
                    'edit' => 'perm_site_admin',
                    'delete' => 'perm_site_admin',
                ],
            ],
            'organisation' => ['model' => 'Organisation', 'writeAdminOnly' => true],
            'user' => ['model' => 'User', 'adminOnly' => true],
        ];
    }

    private function asRole(array $flags): void
    {
        $this->shell->__user = [
            'id' => 195,
            'org_id' => 316,
            'Role' => $flags + [
                'perm_site_admin' => 0,
                'perm_tag_editor' => 0,
                'perm_admin' => 0,
            ],
        ];
    }

    public function testSiteAdminMayWriteEverything(): void
    {
        $this->asRole(['perm_site_admin' => 1]);
        foreach (['event', 'tag', 'organisation', 'user'] as $entity) {
            foreach (['add', 'edit', 'delete'] as $op) {
                $this->assertTrue($this->shell->canWrite($entity, $op), "$entity/$op");
            }
        }
    }

    public function testStockUserCannotTouchTags(): void
    {
        $this->asRole([]);
        $this->assertFalse($this->shell->canWrite('tag', 'add'));
        $this->assertFalse($this->shell->canWrite('tag', 'edit'));
        $this->assertFalse($this->shell->canWrite('tag', 'delete'));
        // ...but events stay open at this level; ownership is checked per record.
        $this->assertTrue($this->shell->canWrite('event', 'edit'));
    }

    public function testTagEditorMayAddButNotEditOrDeleteTags(): void
    {
        $this->asRole(['perm_tag_editor' => 1]);
        $this->assertTrue($this->shell->canWrite('tag', 'add'));
        $this->assertFalse($this->shell->canWrite('tag', 'edit'));
        $this->assertFalse($this->shell->canWrite('tag', 'delete'));
    }

    public function testAdminOnlyAndWriteAdminOnlyRefuseOrgAdmins(): void
    {
        $this->asRole(['perm_admin' => 1, 'perm_tag_editor' => 1]);
        foreach (['add', 'edit', 'delete'] as $op) {
            $this->assertFalse($this->shell->canWrite('organisation', $op), "organisation/$op");
            $this->assertFalse($this->shell->canWrite('user', $op), "user/$op");
        }
    }

    public function testDenialMessageNamesTheMissingPermission(): void
    {
        $this->asRole([]);
        $this->shell->deny('tag', 'add');
        $this->shell->deny('tag', 'delete');
        $this->shell->deny('user', 'edit');
        $this->assertSame(
            [
                'Permission denied: add tag requires the perm_tag_editor permission.',
                'Permission denied: delete tag requires site admin access.',
                'Permission denied: edit user requires site admin access.',
            ],
            $this->shell->errors
        );
    }

    public function testInvalidLimitsFallBackToTheDefaultPageSize(): void
    {
        foreach (['0', '-1', 'abc', '', null] as $limit) {
            $out = $this->shell->paginate(['limit' => $limit]);
            $this->assertSame(20, $out['limit'], var_export($limit, true));
        }
        $out = $this->shell->paginate([]);
        $this->assertSame(20, $out['limit']);
        $this->assertSame(1, $out['page']);
    }

    public function testLimitIsCappedAndPageFloored(): void
    {
        $out = $this->shell->paginate(['limit' => '5000', 'page' => '0']);
        $this->assertSame(1000, $out['limit']);
        $this->assertSame(1, $out['page']);

        $out = $this->shell->paginate(['limit' => '5', 'page' => '3']);
        $this->assertSame(5, $out['limit']);
        $this->assertSame(3, $out['page']);

        $out = $this->shell->paginate(['limit' => '1000', 'page' => 'x']);
        $this->assertSame(1000, $out['limit']);
        $this->assertSame(1, $out['page']);
    }

    public function testOtherFiltersAreLeftAlone(): void
    {
        $out = $this->shell->paginate(['eventid' => '7210', 'limit' => '10']);
        $this->assertSame('7210', $out['eventid']);
    }
}
