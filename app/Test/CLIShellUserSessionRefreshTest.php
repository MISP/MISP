<?php
/**
 * CLIUsersTrait session refresh unit tests.
 * Pure — no DB, no CakePHP bootstrap. The trait is used by a small
 * harness class whose prompts and model are doubles.
 * A logged-in session reloads its user only when `date_modified` has
 * grown (AppController::__verifyUser()), and Model::save() drops every
 * field User::beforeSave() sets that the field list does not name. The
 * CLI's user edit and disable must therefore list `date_modified`, or a
 * user disabled, demoted or moved there keeps the old state in every
 * open session. The admin is never prompted for it.
 */

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../Console/Command/CLIShell/cli_users.php';

class CLIShellUserSessionRefreshFakeUser
{
    public $id;
    public $validationErrors = [];
    public $saves = [];

    public function find($type, $options = [])
    {
        return ['User' => ['id' => 5, 'email' => 'user@test.local', 'disabled' => false]];
    }

    public function save($data, $validate = true, $fieldList = [])
    {
        $this->saves[] = ['data' => $data, 'fieldList' => $fieldList];
        return $data;
    }
}

class CLIShellUserSessionRefreshHarness
{
    use CLIUsersTrait;

    public $__user = ['id' => 1];
    public $__entityConfig = [];
    public $__stdin;
    public $User;
    public $prompted = [];

    public function __construct()
    {
        $this->__entityConfig = $this->__getUserEntityConfig();
        $this->User = new CLIShellUserSessionRefreshFakeUser();
    }

    public function out($message = null, $newlines = 1)
    {
    }

    public function err($message = null, $newlines = 1)
    {
    }

    private function __fetchUserDetail($id)
    {
        return $this->User->find('first');
    }

    private function __promptForFields($entity, $current, $fields)
    {
        $this->prompted = $fields;
        return ['role_id' => '6', 'disabled' => '1'];
    }

    private function __promptConfirm($question)
    {
        return true;
    }

    private function __logUserEdit($id, array $before, array $values)
    {
    }

    public function edit($id)
    {
        return $this->__editUser($id);
    }

    public function disable($id)
    {
        $this->__stdin = fopen('php://memory', 'r+');
        fwrite($this->__stdin, "d\n");
        rewind($this->__stdin);
        $this->__deleteUser($id);
    }
}

class CLIShellUserSessionRefreshTest extends TestCase
{
    /** @var CLIShellUserSessionRefreshHarness */
    private $shell;

    protected function setUp(): void
    {
        $this->shell = new CLIShellUserSessionRefreshHarness();
    }

    public function testEditSavesDateModified(): void
    {
        $this->assertTrue($this->shell->edit(5));
        $saves = $this->shell->User->saves;
        $this->assertCount(1, $saves);
        $this->assertContains('role_id', $saves[0]['fieldList']);
        $this->assertContains('date_modified', $saves[0]['fieldList']);
    }

    public function testEditDoesNotPromptForDateModified(): void
    {
        $this->shell->edit(5);
        $this->assertNotEmpty($this->shell->prompted);
        $this->assertNotContains('date_modified', $this->shell->prompted);
    }

    public function testDisableSavesDateModified(): void
    {
        $this->shell->disable(5);
        $saves = $this->shell->User->saves;
        $this->assertCount(1, $saves);
        $this->assertSame(1, $saves[0]['data']['User']['disabled']);
        $this->assertContains('date_modified', $saves[0]['fieldList']);
    }
}
