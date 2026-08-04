<?php
/**
 * ServerSyncTool feature-negotiation unit tests for collection sync (T5.3 — PRD §6.8).
 *
 * The NEGATIVE control for the collection-sync negotiation triad (const +
 * getVersion advertise + isSupported case, landed in T3.1). The positive path
 * — two feature-code instances both advertising `collection_sync` ⇒ the pull/push
 * collection blocks fire — is already proven by the live 5007⇄5008 E2E (T6.1).
 * These tests pin the OTHER side: a peer that does NOT advertise `collection_sync`
 * (an older instance) makes isSupported(FEATURE_COLLECTION_SYNC) return false, so
 * `Server::pull`/`Server::push` skip the collection blocks silently and no
 * `/collections/*` round-trip is attempted.
 *
 * Pure PHPUnit, no CakePHP bootstrap, no DB (the convention used by every other
 * test under app/Test/ — see CollectionCaptureTest / DashboardURLValidatorTest).
 * isSupported() reads $this->info() (the remote getVersion payload); we drive it
 * through a TestableServerSync subclass that skips the socket-building constructor
 * and returns an injected $info array from info(), so isSupported operates on the
 * exact advertised metadata a real remote would return.
 */

require_once __DIR__ . '/../Vendor/autoload.php';

use PHPUnit\Framework\TestCase;

// -------- framework stub (must exist BEFORE ServerSyncTool.php loads) --------
// ServerSyncTool.php calls App::uses('SyncTool'/'JsonTool', 'Tools') at load
// time; neither is touched by isSupported()/info(), so a no-op resolver suffices.
if (!class_exists('App', false)) {
    class App
    {
        public static function uses($class, $package)
        {
        }
    }
}

require_once __DIR__ . '/../Lib/Tools/ServerSyncTool.php';

/**
 * ServerSyncTool with the HTTP layer removed: the constructor is bypassed (no
 * socket), and info() returns the injected remote-getVersion payload verbatim.
 */
class TestableServerSync extends ServerSyncTool
{
    private $injectedInfo;

    // Deliberately does NOT call parent::__construct (which builds an HttpSocket).
    public function __construct(array $info)
    {
        $this->injectedInfo = $info;
    }

    public function info()
    {
        return $this->injectedInfo;
    }
}

class ServerSyncCollectionNegotiationTest extends TestCase
{
    /** A minimal valid getVersion payload; individual tests layer capability keys on top. */
    private function remoteInfo(array $extra = array())
    {
        return array_merge(array('version' => '2.5.42'), $extra);
    }

    // ---- collection_sync advertised ⇒ supported --------------------------------

    public function testSupportedWhenAdvertisedTrue()
    {
        $sync = new TestableServerSync($this->remoteInfo(array('collection_sync' => true)));
        $this->assertTrue($sync->isSupported(ServerSyncTool::FEATURE_COLLECTION_SYNC));
    }

    public function testSupportedWhenAdvertisedTruthyInt()
    {
        // getVersion advertises `=> true`, but the check is a truthiness test
        // (isset && $info[...]); a truthy 1 from a JSON round-trip still counts.
        $sync = new TestableServerSync($this->remoteInfo(array('collection_sync' => 1)));
        $this->assertTrue($sync->isSupported(ServerSyncTool::FEATURE_COLLECTION_SYNC));
    }

    // ---- old / non-advertising peer ⇒ NOT supported (the negative control) ------

    public function testUnsupportedWhenKeyAbsent()
    {
        // An older instance's getVersion simply omits the key.
        $sync = new TestableServerSync($this->remoteInfo());
        $this->assertFalse($sync->isSupported(ServerSyncTool::FEATURE_COLLECTION_SYNC));
    }

    public function testUnsupportedWhenAdvertisedFalse()
    {
        $sync = new TestableServerSync($this->remoteInfo(array('collection_sync' => false)));
        $this->assertFalse($sync->isSupported(ServerSyncTool::FEATURE_COLLECTION_SYNC));
    }

    public function testUnsupportedWhenAdvertisedFalsyZero()
    {
        $sync = new TestableServerSync($this->remoteInfo(array('collection_sync' => 0)));
        $this->assertFalse($sync->isSupported(ServerSyncTool::FEATURE_COLLECTION_SYNC));
    }

    // ---- harness positive control ----------------------------------------------
    // Proves info() injection actually reaches the switch: a DIFFERENT advertised-
    // boolean flag (filter_sightings, the sibling isSupported case collection_sync
    // was modelled on) flips true/false with the injected payload. Without this, an
    // always-empty info() would make every negative assertion above pass vacuously.

    public function testHarnessInjectsInfo_siblingFlagTogglesTrue()
    {
        $sync = new TestableServerSync($this->remoteInfo(array('filter_sightings' => true)));
        $this->assertTrue($sync->isSupported(ServerSyncTool::FEATURE_FILTER_SIGHTINGS));
    }

    public function testHarnessInjectsInfo_siblingFlagTogglesFalse()
    {
        $sync = new TestableServerSync($this->remoteInfo());
        $this->assertFalse($sync->isSupported(ServerSyncTool::FEATURE_FILTER_SIGHTINGS));
    }
}
