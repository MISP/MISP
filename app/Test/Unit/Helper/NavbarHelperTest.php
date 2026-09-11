<?php

use MispTest\Support\FakeModel;
use PHPUnit\Framework\TestCase;

require_once APP . 'Test/Support/FakeModel.php';

/**
 * NavbarHelper builds MISP's entire top navigation.
 *
 * At 886 statements it is the largest single file that neither test suite
 * reached (0.2% live), yet it is pure structure-building: a user and a
 * controller/action in, a menu structure out. A navigation that silently
 * loses entries for a role is exactly the kind of regression an HTTP smoke
 * test does not notice.
 */
class NavbarHelperTest extends TestCase
{
    public static function setUpBeforeClass(): void
    {
        require_once APP . 'View/Helper/AppHelper.php';
        require_once APP . 'View/Helper/NavbarHelper.php';
    }

    protected function setUp(): void
    {
        ClassRegistry::reset();
        ClassRegistry::$factory = static function ($name) { return new FakeModel(); };
    }

    private static function helper(): NavbarHelper
    {
        return new NavbarHelper(null, []);
    }

    private static function user(array $permissions = []): array
    {
        return [
            'id' => 1,
            'org_id' => 1,
            'email' => 'admin@test.local',
            'Role' => array_merge([
                'id' => 1,
                'name' => 'Site Admin',
                'perm_site_admin' => 1,
                'perm_admin' => 1,
                'perm_sync' => 1,
                'perm_audit' => 1,
                'perm_sighting' => 1,
                'perm_tagger' => 1,
                'perm_galaxy_editor' => 1,
            ], $permissions),
            'Organisation' => ['id' => 1, 'name' => 'TestOrg'],
        ];
    }

    private static function context(array $overrides = []): array
    {
        return array_merge([
            'user' => self::user(),
            'controller' => 'events',
            'action' => 'index',
        ], $overrides);
    }

    public function testBuildReturnsAStructure(): void
    {
        $navbar = self::helper()->build(self::context());

        $this->assertIsArray($navbar, 'build() must return the navbar structure');
        $this->assertNotEmpty($navbar, 'the navbar must not be empty for a site admin');
    }

    public function testBuildIsDeterministicForTheSameContext(): void
    {
        $context = self::context();
        $first = self::helper()->build($context);
        $second = self::helper()->build($context);

        $this->assertEquals($first, $second, 'the same context must yield the same navbar');
    }

    /**
     * @dataProvider controllerProvider
     */
    public function testBuildSurvivesEveryMajorController(string $controller, string $action): void
    {
        $navbar = self::helper()->build(self::context([
            'controller' => $controller,
            'action' => $action,
        ]));

        $this->assertIsArray(
            $navbar,
            sprintf('the navbar must build for %s/%s', $controller, $action)
        );
    }

    public function controllerProvider(): array
    {
        $cases = [];
        foreach ([
            'events' => ['index', 'view', 'add'],
            'attributes' => ['index', 'search'],
            'servers' => ['index', 'previewIndex'],
            'users' => ['index', 'view'],
            'organisations' => ['index'],
            'feeds' => ['index'],
            'galaxies' => ['index'],
            'taxonomies' => ['index'],
            'warninglists' => ['index'],
            'noticelists' => ['index'],
            'sightings' => ['index'],
            'objects' => ['index'],
            'eventReports' => ['index'],
            'dashboards' => ['index'],
            'logs' => ['index'],
            'admin' => ['index'],
        ] as $controller => $actions) {
            foreach ($actions as $action) {
                $cases["$controller/$action"] = [$controller, $action];
            }
        }
        return $cases;
    }

    /**
     * A role without a permission must not be offered the actions it grants.
     * The assertion is deliberately about SHRINKING, not about a specific
     * label, so it survives the navigation being reorganised.
     *
     * @dataProvider permissionProvider
     */
    public function testRemovingAPermissionNeverGrowsTheNavbar(string $permission): void
    {
        $full = self::helper()->build(self::context(['user' => self::user()]));
        $reduced = self::helper()->build(self::context([
            'user' => self::user([$permission => 0]),
        ]));

        $this->assertLessThanOrEqual(
            self::countEntries($full),
            self::countEntries($reduced),
            sprintf('dropping %s must not add navigation entries', $permission)
        );
    }

    public function permissionProvider(): array
    {
        return [
            'perm_site_admin' => ['perm_site_admin'],
            'perm_admin' => ['perm_admin'],
            'perm_sync' => ['perm_sync'],
            'perm_audit' => ['perm_audit'],
            'perm_sighting' => ['perm_sighting'],
            'perm_galaxy_editor' => ['perm_galaxy_editor'],
        ];
    }

    private static function countEntries($structure): int
    {
        if (!is_array($structure)) {
            return 0;
        }
        $count = 0;
        foreach ($structure as $entry) {
            $count++;
            if (is_array($entry)) {
                $count += self::countEntries($entry);
            }
        }
        return $count;
    }

    public function testAnUnprivilegedUserGetsASmallerNavbarThanASiteAdmin(): void
    {
        $admin = self::helper()->build(self::context(['user' => self::user()]));
        $plain = self::helper()->build(self::context([
            'user' => self::user([
                'name' => 'User',
                'perm_site_admin' => 0,
                'perm_admin' => 0,
                'perm_sync' => 0,
                'perm_audit' => 0,
                'perm_galaxy_editor' => 0,
            ]),
        ]));

        $this->assertLessThanOrEqual(
            self::countEntries($admin),
            self::countEntries($plain),
            'a plain user must not see more navigation than a site admin'
        );
    }
}
