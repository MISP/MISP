<?php
/**
 * Cached export file naming: the organisation name must never reach the path.
 */

require_once __DIR__ . '/../Vendor/autoload.php';
require_once __DIR__ . '/../Lib/Tools/CachedExportTool.php';

use PHPUnit\Framework\TestCase;

class CachedExportFileNameTest extends TestCase
{
    private function user($orgId, $admin = false, $orgName = 'x')
    {
        return [
            'org_id' => $orgId,
            'Role' => ['perm_site_admin' => $admin],
            'Organisation' => ['name' => $orgName],
        ];
    }

    public function testOrgNameNeverShapesTheOwner()
    {
        foreach (['ADMIN', '../x', 'a/b', '..'] as $name) {
            $owner = CachedExportTool::owner($this->user(7, false, $name));
            $this->assertSame('7', $owner);
            $file = CachedExportTool::fileName('json', '', $owner, '.json');
            $this->assertSame('misp.json.7.json', $file);
            $this->assertSame(basename($file), $file);
        }
    }

    public function testAdminMarkerCannotCollideWithAnOrg()
    {
        $admin = CachedExportTool::owner($this->user(1, true));
        $this->assertSame('ADMIN', $admin);
        foreach ([0, 1, 2, 'ADMIN', '../x'] as $id) {
            $this->assertNotSame($admin, CachedExportTool::owner($this->user($id)));
        }
        $this->assertNotSame(
            CachedExportTool::fileName('json', '', $admin, '.json'),
            CachedExportTool::fileName('json', '', CachedExportTool::owner($this->user(1)), '.json')
        );
    }

    public function testSubTypeIsPartOfTheName()
    {
        $this->assertSame('misp.text_md5.3.txt', CachedExportTool::fileName('text', 'md5', '3', '.txt'));
        $this->assertSame('misp.bro.ADMIN.intel', CachedExportTool::fileName('bro', '', 'ADMIN', '.intel'));
    }
}
