<?php
/** Run with app/Vendor/bin/phpunit app/Test/CRUDComponentEditTest.php. No DB needed. */
require_once __DIR__ . '/../Vendor/autoload.php';

use PHPUnit\Framework\TestCase;

/**
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 */
class CRUDComponentEditTest extends TestCase
{
    const STORED_UUID = '5f2c8a6e-1b3d-4c7e-9a10-2b3c4d5e6f70';
    const POSTED_UUID = '11111111-2222-4333-8444-555555555555';

    protected function setUp(): void
    {
        require_once __DIR__ . '/CRUDComponentStubs.php';
    }

    private function edit(array $stored, array $input, array $params = [])
    {
        $model = new CrudStubModel(['Collection' => $stored]);
        $crud = new CRUDComponent();
        $crud->initialize(new CrudStubController($model, $input));
        $crud->edit(3, $params);
        return $model->saved['Collection'];
    }

    public function testPostedUuidIsIgnored()
    {
        $saved = $this->edit(
            ['id' => 3, 'uuid' => self::STORED_UUID, 'name' => 'old'],
            ['Collection' => ['uuid' => self::POSTED_UUID, 'name' => 'new']]
        );
        $this->assertSame(self::STORED_UUID, $saved['uuid']);
        $this->assertSame('new', $saved['name']);
    }

    public function testUnwrappedPayloadCannotChangeUuid()
    {
        $saved = $this->edit(
            ['id' => 3, 'uuid' => self::STORED_UUID, 'name' => 'old'],
            ['uuid' => self::POSTED_UUID, 'name' => 'new']
        );
        $this->assertSame(self::STORED_UUID, $saved['uuid']);
    }

    public function testOverrideCannotChangeUuid()
    {
        $saved = $this->edit(
            ['id' => 3, 'uuid' => self::STORED_UUID],
            ['Collection' => ['name' => 'new']],
            ['override' => ['uuid' => self::POSTED_UUID]]
        );
        $this->assertSame(self::STORED_UUID, $saved['uuid']);
    }

    public function testUuidListedInFieldsIsEditable()
    {
        $saved = $this->edit(
            ['id' => 3, 'uuid' => self::STORED_UUID, 'name' => 'old'],
            ['Collection' => ['uuid' => self::POSTED_UUID, 'name' => 'new']],
            ['fields' => ['name', 'uuid']]
        );
        $this->assertSame(self::POSTED_UUID, $saved['uuid']);
    }

    public function testModelWithoutUuidGetsNone()
    {
        $saved = $this->edit(
            ['id' => 3, 'name' => 'old'],
            ['Collection' => ['name' => 'new']]
        );
        $this->assertArrayNotHasKey('uuid', $saved);
        $this->assertSame('new', $saved['name']);
    }
}
