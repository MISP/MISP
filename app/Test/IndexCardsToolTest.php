<?php
if (!class_exists('App')) {
    class App
    {
        public static function uses($className, $location)
        {
        }
    }
}
require_once __DIR__ . '/../Lib/Tools/ModuleLocality.php';
require_once __DIR__ . '/../Lib/Tools/ValueIntelligence/ValueEnrichmentTool.php';
require_once __DIR__ . '/../Lib/Tools/ValueIntelligence/ValueLabelPriority.php';
require_once __DIR__ . '/../Lib/Tools/AnalystProfile/ModuleCredentials.php';
require_once __DIR__ . '/../Lib/Tools/AnalystProfile/IndexCardsTool.php';

use PHPUnit\Framework\TestCase;

class IndexCardsToolTest extends TestCase
{
    private function module($name, array $config = array(), $types = null)
    {
        $module = array(
            'name' => $name,
            'mispattributes' => array('input' => array('ip-src')),
            'meta' => array('config' => $config),
        );
        if ($types !== null) {
            $module['meta']['module-type'] = $types;
        }
        return $module;
    }

    private function reader(array $settings)
    {
        return function ($key) use ($settings) {
            return isset($settings[$key]) ? $settings[$key] : null;
        };
    }

    private function profile($name, array $autoRun, array $context = array())
    {
        return array('name' => $name, 'parameters' => array(
            'enrichment' => array('auto_run' => $autoRun),
            'context' => $context,
        ));
    }

    private function answers($module, $state, $message, $count)
    {
        return array_fill(0, $count, array(
            'module' => $module, 'state' => $state, 'message' => $message));
    }

    public function testTheCatalogueKeepsEnrichmentModulesOnly(): void
    {
        $this->assertNull(IndexCardsTool::catalogue('Module service not reachable.'));
        $catalogue = IndexCardsTool::catalogue(array(
            $this->module('dns'),
            $this->module('circl_passivessl', array('username', 'password'),
                array('expansion', 'hover')),
            $this->module('csvimport', array(), array('import')),
            array('name' => 'no_input', 'meta' => array()),
        ));
        $this->assertSame(array(
            'dns' => array(),
            'circl_passivessl' => array('username', 'password'),
        ), $catalogue);
    }

    public function testNeverAsksForNothingAndAutoIsRemembered(): void
    {
        $asked = IndexCardsTool::askedModules(array(
            $this->profile('A', array(
                'domain' => array('rdap' => 'auto', 'whois' => 'ticked'),
                'ip-src' => array('whois' => 'never'),
            )),
            $this->profile('B', array('hostname' => array('rdap' => 'ticked'))),
        ));
        $this->assertSame(array('rdap', 'whois'), array_keys($asked));
        $this->assertSame(array('A', 'B'), $asked['rdap']['profiles']);
        $this->assertSame(array('domain', 'hostname'), $asked['rdap']['types']);
        $this->assertTrue($asked['rdap']['auto']);
        $this->assertSame(array('domain'), $asked['whois']['types']);
        $this->assertFalse($asked['whois']['auto']);
    }

    public function testOneMessageOnEveryAnswerIsAFault(): void
    {
        $failing = IndexCardsTool::failing(array_merge(
            $this->answers('whois', 'error', 'Whois local instance address is missing', 19),
            $this->answers('reversedns', 'ok', null, 6),
            $this->answers('reversedns', 'error', 'NXDOMAIN', 4),
            $this->answers('dns', 'error', 'NXDOMAIN', 2),
            $this->answers('mmdb_lookup', 'error', 'Timeout', 3),
            $this->answers('mmdb_lookup', 'error', 'Empty result', 3),
            $this->answers('ipasn', 'timeout', '', 3),
            $this->answers('rdap', 'running', null, 5)
        ));
        $this->assertSame(array(
            'whois' => array('count' => 19,
                'message' => 'Whois local instance address is missing'),
            'ipasn' => array('count' => 3, 'message' => 'timeout'),
        ), $failing);
    }

    public function testModuleStatePrecedence(): void
    {
        $catalogue = array('a' => array(), 'circl_passivessl' => array('username', 'password'),
            'c' => array(), 'd' => array(), 'e' => array());
        $read = $this->reader(array(
            'Plugin.Enrichment_a_enabled' => false,
            'Plugin.Enrichment_circl_passivessl_enabled' => false,
            'Plugin.Enrichment_c_enabled' => true,
            'Plugin.Enrichment_c_restrict' => '9',
            'Plugin.Enrichment_d_enabled' => true,
            'Plugin.Enrichment_e_enabled' => true,
        ));
        $failing = array('d' => array('count' => 3, 'message' => 'x'));
        $state = function ($name, $org = null) use ($catalogue, $read, $failing) {
            return IndexCardsTool::moduleState($name, $catalogue, $read,
                $failing, $org)['state'];
        };
        $this->assertSame('missing', $state('z'));
        $this->assertSame('off', $state('a'));
        $this->assertSame('settings', $state('circl_passivessl'));
        $this->assertSame(array('username', 'password'), IndexCardsTool::moduleState(
            'circl_passivessl', $catalogue, $read)['unset']);
        $this->assertSame('restricted', $state('c'));
        $this->assertSame('restricted', $state('c', 1));
        $this->assertSame('ready', $state('c', 9));
        $this->assertSame('failing', $state('d'));
        $this->assertSame('ready', $state('e'));
    }

    private function devInstance()
    {
        $profiles = array(
            $this->profile('default', array(
                'ip-src' => array('circl_passivessl' => 'ticked', 'mmdb_lookup' => 'ticked'),
                'domain' => array('rdap' => 'auto', 'whois' => 'ticked', 'dns' => 'ticked'),
                'vulnerability' => array('cve' => 'ticked'),
            )),
            $this->profile('SOC Triage', array(
                'domain' => array('rdap' => 'auto'),
            ), array('taxonomies' => array(
                'pinned' => array('tlp', 'false-positive'),
                'preferred' => array('malware_classification'),
                'demoted' => array('veris'),
            ))),
        );
        $modules = array(
            $this->module('circl_passivessl', array('username', 'password')),
            $this->module('mmdb_lookup'),
            $this->module('whois', array('server', 'port')),
            $this->module('dns'),
            $this->module('cve'),
        );
        $settings = array(
            'Plugin.Enrichment_services_enable' => true,
            'Plugin.ValueIntelligence_enrichment_auto_run' => 'on',
            'Plugin.Enrichment_mmdb_lookup_enabled' => true,
            'Plugin.Enrichment_whois_enabled' => true,
            'Plugin.Enrichment_dns_enabled' => true,
        );
        $taxonomies = array(
            'tlp' => array('id' => 1, 'namespace' => 'tlp', 'enabled' => 1),
            'false-positive' => array('id' => 2, 'namespace' => 'false-positive', 'enabled' => 0),
            'veris' => array('id' => 4, 'namespace' => 'veris', 'enabled' => 0),
        );
        return array($profiles, $modules, $settings, $taxonomies);
    }

    public function testTheDiagnosticGroupsByFix(): void
    {
        list($profiles, $modules, $settings, $taxonomies) = $this->devInstance();
        $card = IndexCardsTool::diagnostic($profiles, $modules,
            $this->reader($settings),
            $this->answers('whois', 'error', 'Whois local instance address is missing', 5),
            $taxonomies);
        $this->assertSame('on', $card['service']);
        $this->assertSame(6, $card['asked']);
        $this->assertSame(1, $card['auto']);
        $this->assertSame(2, $card['ready']);
        $this->assertSame(array('off', 'settings', 'failing', 'missing'),
            array_keys($card['groups']));
        $this->assertSame('cve', $card['groups']['off'][0]['name']);
        $this->assertSame('circl_passivessl', $card['groups']['settings'][0]['name']);
        $this->assertFalse($card['groups']['settings'][0]['enabled']);
        $this->assertSame('whois', $card['groups']['failing'][0]['name']);
        $this->assertSame(5, $card['groups']['failing'][0]['failing']['count']);
        $this->assertSame('rdap', $card['groups']['missing'][0]['name']);
        $this->assertTrue($card['groups']['missing'][0]['auto']);
        $this->assertSame(array('default', 'SOC Triage'),
            $card['groups']['missing'][0]['profiles']);

        $this->assertSame(array('false-positive'), array_column(
            $card['taxonomies']['off'], 'namespace'));
        $this->assertSame(2, $card['taxonomies']['off'][0]['id']);
        $this->assertSame(array('malware_classification'), array_column(
            $card['taxonomies']['missing'], 'namespace'));
        $this->assertSame(5, $card['attention']);
    }

    public function testTheServiceSwitchComesBeforeAnyModule(): void
    {
        list($profiles, $modules, $settings, $taxonomies) = $this->devInstance();
        $settings['Plugin.Enrichment_services_enable'] = false;
        $card = IndexCardsTool::diagnostic($profiles, $modules,
            $this->reader($settings), array(), $taxonomies);
        $this->assertSame('off', $card['service']);
        $this->assertSame(array(), $card['groups']);
        $this->assertSame(1, $card['attention']);

        $settings['Plugin.Enrichment_services_enable'] = true;
        $card = IndexCardsTool::diagnostic($profiles, 'Module service not reachable.',
            $this->reader($settings), array(), $taxonomies);
        $this->assertSame('unreachable', $card['service']);
        $this->assertSame(array(), $card['groups']);
    }

    public function testTheReaderCardIsTheirOwnProfile(): void
    {
        list($profiles, $modules, $settings) = $this->devInstance();
        $user = array('org_id' => 1, 'Role' => array('perm_add' => true,
            'perm_site_admin' => false));
        $card = IndexCardsTool::reader($profiles[1], $modules,
            $this->reader($settings), $user);
        $this->assertSame('SOC Triage', $card['profile']);
        $this->assertSame(1, $card['asked']);
        $this->assertSame(0, $card['ready']);
        $this->assertSame(array('missing' => array('rdap')), $card['groups']);
        $this->assertSame(array(), $card['auto']);

        $card = IndexCardsTool::reader($profiles[0], $modules,
            $this->reader($settings), $user);
        $this->assertSame(6, $card['asked']);
        $this->assertSame(3, $card['ready']);
        $this->assertSame(array('cve'), $card['groups']['off']);
        $this->assertSame(array('circl_passivessl'), $card['groups']['settings']);
        $this->assertNull($card['auto_held']);
    }

    public function testAnAutoHeldByTheGateIsSaid(): void
    {
        list($profiles, $modules, $settings) = $this->devInstance();
        $modules[] = $this->module('rdap');
        $settings['Plugin.Enrichment_rdap_enabled'] = true;
        $user = array('org_id' => 1, 'Role' => array('perm_add' => true,
            'perm_site_admin' => false));
        foreach (array(null => 'off', 'off' => 'off',
            'site_admin' => 'site_admin', 'on' => null) as $gate => $held
        ) {
            $settings['Plugin.ValueIntelligence_enrichment_auto_run'] = $gate === '' ? null : $gate;
            $card = IndexCardsTool::reader($profiles[1], $modules,
                $this->reader($settings), $user);
            $this->assertSame(array('rdap'), $card['auto'], (string)$gate);
            $this->assertSame($held, $card['auto_held'], (string)$gate);
        }
    }

    private function counted($queries, array $outcomes = array(),
        $average = 0.2, $max = 0.5
    ) {
        $outcomes += array('module_errors' => 0, 'exceptions' => 0,
            'timeouts' => 0);
        $completed = $queries - (isset($outcomes['in_flight'])
            ? $outcomes['in_flight'] : 0);
        unset($outcomes['in_flight']);
        return $outcomes + array(
            'type' => 'expansion',
            'queries' => $queries,
            'completed' => $completed,
            'successes' => $completed - array_sum($outcomes),
            'last_query_at' => $queries ? '2026-10-19T13:05:02.643586+00:00' : null,
            'response_time_seconds' => array(
                'count' => $completed,
                'total' => $completed * $average,
                'average' => $completed ? $average : null,
                'max' => $completed ? $max : null,
            ),
        );
    }

    private function statistics(array $modules)
    {
        return array(
            'started_at' => '2026-10-19T13:05:02.643586+00:00',
            'uptime_seconds' => 7200.5,
            'totals' => array(),
            'modules' => $modules,
        );
    }

    public function testActivityKeepsTheAskedModulesOnly(): void
    {
        $asked = array('dns' => array(), 'whois' => array(),
            'mmdb_lookup' => array(), 'not_loaded' => array());
        $this->assertNull(IndexCardsTool::activity(null, $asked));
        $this->assertNull(IndexCardsTool::activity(array('error' => 'x'), $asked));

        $activity = IndexCardsTool::activity($this->statistics(array(
            'dns' => $this->counted(10, array('module_errors' => 4), 0.1),
            'whois' => $this->counted(30, array('timeouts' => 2,
                'in_flight' => 1), 0.4, 9.0),
            'mmdb_lookup' => $this->counted(0),
            'csvimport' => $this->counted(50),
        )), $asked);
        $this->assertSame(7200.5, $activity['uptime']);
        $this->assertSame(array('whois', 'dns'),
            array_column($activity['modules'], 'name'));
        $this->assertSame(array('mmdb_lookup'), $activity['idle']);
        $this->assertSame(40, $activity['queries']);
        $this->assertSame(39, $activity['completed']);
        $this->assertSame(4, $activity['module_errors']);
        $this->assertSame(2, $activity['timeouts']);
        $this->assertEqualsWithDelta((29 * 0.4 + 10 * 0.1) / 39,
            $activity['average'], 1e-9);
        $this->assertSame(9.0, $activity['modules'][0]['max']);
    }

    public function testTimeoutsAndCrashesMakeAModuleUnstable(): void
    {
        $asked = array_fill_keys(array('a', 'b', 'c', 'd', 'e'), array());
        $unstable = IndexCardsTool::unstable(IndexCardsTool::activity(
            $this->statistics(array(
                'a' => $this->counted(6, array('timeouts' => 2, 'exceptions' => 1)),
                'b' => $this->counted(6, array('timeouts' => 2)),
                'c' => $this->counted(2, array('exceptions' => 2)),
                'd' => $this->counted(9, array('module_errors' => 9)),
                'e' => $this->counted(3, array('exceptions' => 3)),
            )), $asked));
        $this->assertSame(array(
            'a' => array('completed' => 6, 'timeouts' => 2, 'exceptions' => 1),
            'e' => array('completed' => 3, 'timeouts' => 0, 'exceptions' => 3),
        ), $unstable);
        $this->assertSame(array(), IndexCardsTool::unstable(null));
    }

    public function testTheDiagnosticAddsWhatTheServiceCounted(): void
    {
        list($profiles, $modules, $settings, $taxonomies) = $this->devInstance();
        $card = IndexCardsTool::diagnostic($profiles, $modules,
            $this->reader($settings),
            $this->answers('whois', 'error', 'Whois local instance address is missing', 5),
            $taxonomies,
            $this->statistics(array(
                'dns' => $this->counted(5, array('timeouts' => 4)),
                'whois' => $this->counted(5, array('exceptions' => 5)),
                'mmdb_lookup' => $this->counted(8),
            )));
        $this->assertSame(array('off', 'settings', 'failing', 'unstable',
            'missing'), array_keys($card['groups']));
        $this->assertSame('whois', $card['groups']['failing'][0]['name']);
        $this->assertSame('dns', $card['groups']['unstable'][0]['name']);
        $this->assertSame(4, $card['groups']['unstable'][0]['unstable']['timeouts']);
        $this->assertSame(1, $card['ready']);
        $this->assertSame(6, $card['attention']);
        $this->assertSame(18, $card['activity']['queries']);

        $card = IndexCardsTool::diagnostic($profiles, $modules,
            $this->reader($settings), array(), $taxonomies);
        $this->assertNull($card['activity']);
        $this->assertArrayNotHasKey('unstable', $card['groups']);
    }

    public function testAReaderWithNothingInForceOrNoRight(): void
    {
        list(, $modules, $settings) = $this->devInstance();
        $card = IndexCardsTool::reader(null, $modules, $this->reader($settings),
            array('org_id' => 1, 'Role' => array('perm_add' => false)));
        $this->assertNull($card['profile']);
        $this->assertSame(0, $card['asked']);
        $this->assertFalse($card['can_run']);
    }
}
