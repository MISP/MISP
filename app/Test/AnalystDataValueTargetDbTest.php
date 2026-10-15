<?php
/**
 * Analyst data and collection elements on attribute values: which value
 * targets resolve, for whom, and the analyst data read by value. A value no
 * attribute the user can see holds resolves exactly like a value the
 * dictionary lacks; the analyst data on a value follows only its own ACL, as
 * on a uuid.
 *
 * The values are interned before the test's transaction and deleted by id
 * after it; everything else is saved inside the transaction, which is rolled
 * back. The lesser user is user 195, of another organisation than the
 * fixture events and the analyst data.
 *
 * Skipped unless ATTRIBUTE_VALUE_DB_TESTS is set, and it boots the real
 * application, so it must run on its own:
 *     ATTRIBUTE_VALUE_DB_TESTS=1 ./app/Vendor/bin/phpunit app/Test/AnalystDataValueTargetDbTest.php
 */

use PHPUnit\Framework\TestCase;

class AnalystDataValueTargetDbTest extends TestCase
{
    const LESSER_USER = 195;

    // Held by a visible attribute, only by a hidden one, only by a deleted
    // one, by none, and not stored at all
    const KINDS = ['visible', 'hidden', 'deleted', 'unheld', 'missing'];

    private static $booted = false;

    /** @var MispAttribute */
    private $attribute;

    /** @var AttributeValue */
    private $values;

    /** @var Note */
    private $note;

    /** @var Relationship */
    private $relationship;

    /** @var DboSource */
    private $db;

    /** @var array */
    private $admin;

    /** @var array */
    private $lesser;

    /** @var string */
    private $t;

    /** @var array kind => value text */
    private $text = [];

    /** @var array kind => SHA-256 of the text */
    private $hex = [];

    /** @var int[] dictionary ids interned for the test */
    private $interned = [];

    /** @var array name => attribute uuid */
    private $attributes = [];

    /** @var mixed */
    private $currentUserId;

    protected function setUp(): void
    {
        if (!getenv('ATTRIBUTE_VALUE_DB_TESTS')) {
            $this->markTestSkipped('Needs the database, see the file header.');
        }
        if (!self::$booted) {
            if (class_exists('App', false)) {
                $this->markTestSkipped('Needs its own process: run this file alone.');
            }
            require_once __DIR__ . '/OracleBootstrap.php';
            App::uses('ClassRegistry', 'Utility');
            App::uses('AttributeValue', 'Model');
            App::uses('CakeText', 'Utility');
            AttributeValue::$strictConditions = true;
            self::$booted = true;
        }
        $this->attribute = ClassRegistry::init('MispAttribute');
        $this->values = $this->attribute->loadAttributeValue();
        $this->db = $this->attribute->getDataSource();
        if (!($this->db instanceof Mysql)) {
            // Skipped before the fixture exists: nothing for tearDown to clean up
            $this->db = null;
            $this->markTestSkipped('MySQL/MariaDB only.');
        }
        $users = ClassRegistry::init('User');
        $this->admin = $users->getAuthUser(1);
        $this->lesser = $users->getAuthUser(self::LESSER_USER);
        if (empty($this->lesser) || $this->lesser['Role']['perm_site_admin']) {
            $this->markTestSkipped('Needs user 195, without site admin rights.');
        }
        $this->currentUserId = Configure::read('CurrentUserId');
        Configure::write('CurrentUserId', $this->admin['id']);
        $this->note = ClassRegistry::init('Note');
        $this->relationship = ClassRegistry::init('Relationship');
        $this->forgetCachedUsers();

        $this->t = 'vt' . bin2hex(random_bytes(5));
        foreach (self::KINDS as $kind) {
            $this->text[$kind] = "{$this->t}-$kind.example";
            $this->hex[$kind] = hash('sha256', $this->text[$kind]);
        }
        $stored = array_values(array_diff_key($this->text, ['missing' => true]));
        $this->assertEmpty($this->values->idsOf(array_values($this->text)), 'A fixture value is already stored.');
        $this->interned = array_values(array_map('intval', $this->values->internMany($stored)));

        $this->db->begin();
        $this->addAttributes();
        $this->addAnalystData();
    }

    protected function tearDown(): void
    {
        if (!$this->db) {
            return;
        }
        Configure::write('CurrentUserId', $this->currentUserId);
        $this->db->rollback();
        $this->forgetCachedUsers();
        if (!empty($this->interned)) {
            $ids = implode(', ', $this->interned);
            $held = $this->exec("SELECT 1 FROM attributes WHERE value1_id IN ($ids) OR value2_id IN ($ids) LIMIT 1");
            $this->assertEmpty($held, 'An interned fixture value is still referenced.');
            $this->exec("DELETE FROM value_ip_ranges WHERE value_id IN ($ids)");
            $this->exec("DELETE FROM attribute_values WHERE id IN ($ids)");
        }
    }

    private function exec($sql)
    {
        $statement = $this->db->rawQuery($sql);
        if (!($statement instanceof PDOStatement)) {
            return [];
        }
        $rows = $statement->columnCount() > 0 ? $statement->fetchAll(PDO::FETCH_ASSOC) : [];
        $statement->closeCursor();
        return $rows;
    }

    private function firstEvent($where)
    {
        $rows = $this->exec("SELECT id FROM events WHERE $where ORDER BY id LIMIT 1");
        if (empty($rows)) {
            $this->markTestSkipped("Needs an event with $where.");
        }
        return (int)$rows[0]['id'];
    }

    /**
     * The sharing group caches outlive a test: the models are shared through
     * the ClassRegistry, and so is the one AnalystDataBehavior instance.
     */
    private function forgetCachedUsers()
    {
        foreach (ClassRegistry::keys() as $key) {
            $object = ClassRegistry::getObject($key);
            if ($object instanceof SharingGroup) {
                $property = new ReflectionProperty('SharingGroup', 'authorizedIds');
                $property->setAccessible(true);
                $property->setValue($object, []);
            } elseif ($object instanceof AnalystDataBehavior) {
                $property = new ReflectionProperty('AnalystDataBehavior', '__valid_sharing_groups');
                $property->setAccessible(true);
                $property->setValue($object, []);
            }
        }
    }

    /**
     * Saved without correlating. The visible attribute is also the anchor
     * that relationships from and to the values point at.
     */
    private function addAttributes()
    {
        $org = (int)$this->lesser['org_id'];
        $events = [
            'hidden' => $this->firstEvent("distribution = 0 AND org_id <> $org"),
            'open' => $this->firstEvent("distribution = 3 AND published = 1 AND org_id <> $org"),
        ];
        $holders = ['visible' => 'open', 'hidden' => 'hidden', 'deleted' => 'open'];
        foreach ($holders as $kind => $event) {
            $this->attributes[$kind] = CakeText::uuid();
            $this->attribute->create();
            $saved = $this->attribute->save(['Attribute' => [
                'uuid' => $this->attributes[$kind],
                'event_id' => $events[$event],
                'category' => 'Other',
                'type' => 'text',
                'value' => $this->text[$kind],
                'distribution' => 5,
                'to_ids' => 0,
                'disable_correlation' => 1,
            ]]);
            $this->assertNotFalse($saved, $kind . json_encode($this->attribute->validationErrors));
        }
        $this->exec(sprintf("UPDATE attributes SET deleted = 1 WHERE uuid = '%s'", $this->attributes['deleted']));
    }

    /**
     * Per value, by the admin's organisation: a note shared with all, a note
     * kept to the organisation, a reply to the shared note, a relationship
     * from the value to the anchor and one from the anchor to the value.
     */
    private function addAnalystData()
    {
        $anchor = $this->attributes['visible'];
        foreach (self::KINDS as $kind) {
            $hex = $this->hex[$kind];
            $shared = $this->save($this->note, [
                'note' => "{$this->t} $kind shared",
                'object_type' => 'AttributeValue',
                'object_sha256' => $hex,
                'distribution' => 3,
            ]);
            $this->save($this->note, [
                'note' => "{$this->t} $kind own",
                'object_type' => 'AttributeValue',
                'object_sha256' => $hex,
                'distribution' => 0,
            ]);
            $this->save($this->note, [
                'note' => "{$this->t} $kind reply",
                'object_type' => 'Note',
                'object_uuid' => $shared,
                'distribution' => 3,
            ]);
            $this->save($this->relationship, [
                'relationship_type' => "{$this->t}-from-value",
                'object_type' => 'AttributeValue',
                'object_sha256' => $hex,
                'related_object_type' => 'Attribute',
                'related_object_uuid' => $anchor,
                'distribution' => 3,
            ]);
            $this->save($this->relationship, [
                'relationship_type' => "{$this->t}-to-value",
                'object_type' => 'Attribute',
                'object_uuid' => $anchor,
                'related_object_type' => 'AttributeValue',
                'related_object_sha256' => $hex,
                'distribution' => 3,
            ]);
        }
    }

    /**
     * @return string the uuid of the saved row
     */
    private function save(AnalystData $model, array $row)
    {
        $row['uuid'] = CakeText::uuid();
        $model->current_user = $this->admin;
        $model->create();
        $saved = $model->save([$model->current_type => $row]);
        $this->assertNotFalse($saved, json_encode($model->validationErrors));
        return $row['uuid'];
    }

    private function users()
    {
        return ['admin' => $this->admin, 'lesser' => $this->lesser];
    }

    /**
     * @return array the kinds whose value resolves for the user
     */
    private function resolving($userName)
    {
        return $userName === 'admin' ? ['visible', 'hidden'] : ['visible'];
    }

    private function valueElement($kind)
    {
        return ['AttributeValue' => ['value' => $this->text[$kind], 'sha256' => $this->hex[$kind]]];
    }

    public function testFindBySha256ReadsTheDictionary()
    {
        $found = $this->values->findBySha256(array_map('strtoupper', array_values($this->hex)));
        $expected = [];
        foreach (['visible', 'hidden', 'deleted', 'unheld'] as $kind) {
            $expected[$this->hex[$kind]] = (int)$this->values->findAddressed(['value' => $this->text[$kind]])['id'];
        }
        ksort($found);
        ksort($expected);
        $this->assertSame($expected, $found);
    }

    public function testOnlyAValueAVisibleAttributeHoldsIsAnExistingTarget()
    {
        $targets = [
            ['type' => 'Attribute', 'address' => $this->attributes['visible']],
            ['type' => 'Attribute', 'address' => $this->attributes['hidden']],
        ];
        foreach (self::KINDS as $kind) {
            $targets[] = ['type' => 'AttributeValue', 'address' => strtoupper($this->hex[$kind])];
        }
        foreach ($this->users() as $name => $user) {
            $expected = [$this->attributes['visible'] => true];
            if ($name === 'admin') {
                $expected[$this->attributes['hidden']] = true;
            }
            foreach ($this->resolving($name) as $kind) {
                $expected[$this->hex[$kind]] = true;
            }
            $found = $this->note->existingTargets($user, $targets);
            ksort($found);
            ksort($expected);
            $this->assertSame($expected, $found, $name);
        }
    }

    public function testARelatedValueIsEmptyWhenMissingOrNotVisible()
    {
        foreach ($this->users() as $name => $user) {
            foreach (self::KINDS as $kind) {
                $expected = in_array($kind, $this->resolving($name), true) ? $this->valueElement($kind) : [];
                $this->assertSame($expected, $this->relationship->getRelatedElement($user, 'AttributeValue', $this->hex[$kind]), "$name $kind");
                $this->assertSame($expected, $this->relationship->getRelatedElement($user, 'AttributeValue', strtoupper($this->hex[$kind])), "$name $kind upper");
            }
        }
        $this->assertSame([], $this->relationship->getRelatedElement($this->admin, 'AttributeValue', 'not a hash'));
    }

    public function testAFetchedRelationshipCarriesItsValueEndForTheCurrentUser()
    {
        $currentUser = new ReflectionProperty('Relationship', '__currentUser');
        $currentUser->setAccessible(true);
        foreach ($this->users() as $name => $user) {
            Configure::write('CurrentUserId', $user['id']);
            $currentUser->setValue($this->relationship, null);
            $rows = $this->relationship->find('all', [
                'conditions' => ['Relationship.relationship_type' => "{$this->t}-to-value"],
            ]);
            $this->assertCount(count(self::KINDS), $rows, $name);
            $byHex = array_column(array_column($rows, 'Relationship'), 'related_object', 'related_object_sha256');
            foreach (self::KINDS as $kind) {
                $expected = in_array($kind, $this->resolving($name), true) ? $this->valueElement($kind) : [];
                $this->assertSame($expected, $byHex[$this->hex[$kind]], "$name $kind");
            }
        }
    }

    public function testInboundRelationshipsReachAndLeaveAValue()
    {
        $anchor = $this->attributes['visible'];
        foreach ($this->users() as $name => $user) {
            foreach (self::KINDS as $kind) {
                $rows = $this->relationship->getInboundRelationships($user, 'AttributeValue', strtoupper($this->hex[$kind]));
                $this->assertCount(1, $rows, "$name $kind");
                $this->assertSame($anchor, $rows[0]['Relationship']['object_uuid']);
                $this->assertSame($anchor, $rows[0]['Relationship']['related_object']['Attribute']['uuid'], "$name $kind");
            }
            $rows = $this->relationship->getInboundRelationships($user, 'Attribute', $anchor);
            $this->assertCount(count(self::KINDS), $rows, $name);
            $byHex = array_column(array_column($rows, 'Relationship'), 'related_object', 'object_sha256');
            foreach (self::KINDS as $kind) {
                $expected = in_array($kind, $this->resolving($name), true) ? $this->valueElement($kind) : [];
                $this->assertSame($expected, $byHex[$this->hex[$kind]], "$name $kind");
            }
        }
    }

    public function testTheAnalystDataOnAValueFollowsItsOwnAcl()
    {
        $hexes = array_map('strtoupper', array_values($this->hex));
        foreach ($this->users() as $name => $user) {
            $notes = $this->note->fetchForSha256s($hexes, $user);
            $relationships = $this->relationship->fetchForSha256s($hexes, $user);
            $this->assertCount(count(self::KINDS), $notes, $name);
            foreach (self::KINDS as $kind) {
                $expected = ["{$this->t} $kind shared"];
                if ($name === 'admin') {
                    $expected[] = "{$this->t} $kind own";
                }
                $texts = array_column($notes[$this->hex[$kind]]['Note'], 'note');
                sort($texts);
                sort($expected);
                $this->assertSame($expected, $texts, "$name $kind");
                $this->assertCount(1, $relationships[$this->hex[$kind]]['Relationship'], "$name $kind");
            }
            $byUuid = $this->relationship->fetchForUuids([$this->attributes['visible']], $user);
            $this->assertCount(count(self::KINDS), $byUuid[$this->attributes['visible']]['Relationship'], $name);
        }
        $this->assertSame([], $this->note->fetchForSha256s([hash('sha256', $this->t)], $this->lesser));
    }

    public function testAValueCountsItsAnalystDataAtAnyDepth()
    {
        foreach ($this->users() as $name => $user) {
            foreach (self::KINDS as $kind) {
                // Shared note, its reply, the relationships from and to the value; the own note for the admin
                $this->assertSame($name === 'admin' ? 5 : 4, $this->note->countForObjectRecursive($user, strtoupper($this->hex[$kind]), 'AttributeValue'), "$name $kind");
            }
            $this->assertSame(2 * count(self::KINDS), $this->note->countForObjectRecursive($user, $this->attributes['visible']), $name);
        }
    }

    public function testOneUsersSharingGroupsDoNotServeTheNext()
    {
        $org = (int)$this->lesser['org_id'];
        $rows = $this->exec(sprintf(
            'SELECT u.id FROM users u JOIN roles r ON r.id = u.role_id WHERE r.perm_site_admin = 0 AND u.disabled = 0 AND u.org_id NOT IN (%d, %d) ORDER BY u.id LIMIT 1',
            $org,
            (int)$this->admin['org_id']
        ));
        if (empty($rows)) {
            $this->markTestSkipped('Needs a user of a third organisation, without site admin rights.');
        }
        $outsider = ClassRegistry::init('User')->getAuthUser((int)$rows[0]['id']);
        $uuid = CakeText::uuid();
        $this->exec(sprintf(
            "INSERT INTO sharing_groups (name, releasability, description, uuid, organisation_uuid, org_id, sync_user_id, active, created, modified, local, roaming) VALUES ('%s', '', '', '%s', '%s', %d, 0, 1, NOW(), NOW(), 1, 0)",
            $this->t,
            $uuid,
            $this->admin['Organisation']['uuid'],
            (int)$this->admin['org_id']
        ));
        $sharingGroupId = (int)$this->exec("SELECT id FROM sharing_groups WHERE uuid = '$uuid'")[0]['id'];
        $this->exec("INSERT INTO sharing_group_orgs (sharing_group_id, org_id, extend) VALUES ($sharingGroupId, $org, 0)");
        $hex = $this->hex['visible'];
        $this->save($this->note, [
            'note' => "{$this->t} group",
            'object_type' => 'AttributeValue',
            'object_sha256' => $hex,
            'distribution' => 4,
            'sharing_group_id' => $sharingGroupId,
        ]);
        $this->save($this->relationship, [
            'relationship_type' => "{$this->t}-group",
            'object_type' => 'Attribute',
            'object_uuid' => $this->attributes['visible'],
            'related_object_type' => 'AttributeValue',
            'related_object_sha256' => $hex,
            'distribution' => 4,
            'sharing_group_id' => $sharingGroupId,
        ]);
        $this->forgetCachedUsers();

        // The member first, so that a cache shared between users would hand its groups to the outsider
        $this->assertCount(2, $this->note->fetchForSha256s([$hex], $this->lesser)[$hex]['Note']);
        $this->assertCount(1, $this->note->fetchForSha256s([$hex], $outsider)[$hex]['Note']);
        $this->assertCount(2, $this->relationship->getInboundRelationships($this->lesser, 'AttributeValue', $hex));
        $this->assertCount(1, $this->relationship->getInboundRelationships($outsider, 'AttributeValue', $hex));
    }

    public function testOnlyAValueTheUserCanSeeGoesIntoACollection()
    {
        $elements = ClassRegistry::init('CollectionElement');
        $refusal = function ($user, $type, $address) use ($elements) {
            try {
                $elements->assertTargetsUsable($user, $type, [$address]);
            } catch (NotFoundException $e) {
                return $e->getMessage();
            }
            return null;
        };
        foreach ($this->users() as $name => $user) {
            foreach (self::KINDS as $kind) {
                $expected = in_array($kind, $this->resolving($name), true) ? null : 'Invalid value or not authorized.';
                $this->assertSame($expected, $refusal($user, 'AttributeValue', strtoupper($this->hex[$kind])), "$name $kind");
            }
        }
        // A hash is never deduced to be a value, and an unknown type is refused
        $this->assertNotNull($refusal($this->admin, null, $this->hex['visible']));
        $this->assertSame('Invalid element type.', $refusal($this->admin, 'Unknown', $this->hex['visible']));
    }

    public function testACapturedValueElementKeepsItsAddressOnce()
    {
        $this->exec(sprintf(
            "INSERT INTO collections (uuid, org_id, orgc_id, user_id, distribution, name, type) VALUES ('%s', %d, %d, %d, 0, '%s', 'other')",
            CakeText::uuid(),
            (int)$this->admin['org_id'],
            (int)$this->admin['org_id'],
            (int)$this->admin['id'],
            $this->t
        ));
        $collectionId = (int)$this->exec("SELECT id FROM collections WHERE name = '{$this->t}'")[0]['id'];
        $elements = ClassRegistry::init('CollectionElement');
        // Sync capture keeps a value this instance cannot resolve
        $elements->captureElements(['Collection' => ['id' => $collectionId, 'CollectionElement' => [
            ['element_type' => 'AttributeValue', 'element_sha256' => strtoupper($this->hex['missing'])],
        ]]]);
        $this->assertSame(
            [['element_type' => 'AttributeValue', 'element_uuid' => null, 'element_sha256' => $this->hex['missing']]],
            $this->exec("SELECT element_type, element_uuid, element_sha256 FROM collection_elements WHERE collection_id = $collectionId")
        );

        $elements->create();
        try {
            $elements->save(['CollectionElement' => [
                'collection_id' => $collectionId,
                'element_type' => 'AttributeValue',
                'element_sha256' => $this->hex['missing'],
            ]]);
            $this->fail('A second copy of the value element was saved.');
        } catch (PDOException $e) {
            $this->assertTrue(CollectionElement::isDuplicate($e), json_encode($e->errorInfo));
        }
        $postgres = new PDOException('duplicate key value violates unique constraint');
        $postgres->errorInfo = ['23505', 7, ''];
        $this->assertTrue(CollectionElement::isDuplicate($postgres));
        $other = new PDOException('relation does not exist');
        $other->errorInfo = ['42P01', 7, ''];
        $this->assertFalse(CollectionElement::isDuplicate($other));
    }
}
