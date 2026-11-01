<?php
/**
 * MispAttribute attachment-type unit tests.
 *
 * Pure PHPUnit, no CakePHP bootstrap, no DB - the convention used by the other
 * tests under app/Test/ (see CollectionCaptureTest and UserCanSeeEmailsTest).
 * MispAttribute is a model, so we stub App/AppModel before loading the real
 * MispAttribute.php, then drive the attachment-type helpers through a
 * TestableMispAttribute subclass whose constructor is a no-op (the real one
 * only builds translated distribution labels, which this test does not need).
 *
 * The point of the test is the invariant the attachment database conditions
 * rely on: ATTACHMENT_TYPES is the union of UPLOAD_DEFINITIONS and
 * ZIPPED_DEFINITION, and typeIsAttachment() answers from that same list. Add a
 * third attachment-bearing type to one of the definitions and forget the union
 * and this test fails instead of the download/listing queries silently
 * returning nothing for it.
 */

require_once __DIR__ . '/../Vendor/autoload.php';

// -------- framework stubs (must exist BEFORE MispAttribute.php loads) --------

if (!class_exists('App', false)) {
    class App
    {
        public static function uses($class, $package)
        {
        }
    }
}

if (!class_exists('AppModel', false)) {
    class AppModel
    {
        public function __construct($id = false, $table = null, $ds = null)
        {
        }
    }
}

require_once __DIR__ . '/../Model/MispAttribute.php';

use PHPUnit\Framework\TestCase;

class TestableMispAttribute extends MispAttribute
{
    public function __construct()
    {
    }
}

class MispAttributeAttachmentTypesTest extends TestCase
{
    public function testAttachmentTypesIsTheUnionOfTheUploadDefinitions(): void
    {
        $union = array_unique(array_merge(
            MispAttribute::UPLOAD_DEFINITIONS,
            MispAttribute::ZIPPED_DEFINITION
        ));
        sort($union);
        $attachmentTypes = MispAttribute::ATTACHMENT_TYPES;
        sort($attachmentTypes);
        $this->assertSame($union, $attachmentTypes);
    }

    public function testTypeIsAttachmentAgreesWithAttachmentTypes(): void
    {
        $attribute = new TestableMispAttribute();
        foreach (MispAttribute::ATTACHMENT_TYPES as $type) {
            $this->assertTrue($attribute->typeIsAttachment($type));
        }
        $this->assertFalse($attribute->typeIsAttachment('md5'));
        $this->assertFalse($attribute->typeIsAttachment('ip-src'));
    }
}
