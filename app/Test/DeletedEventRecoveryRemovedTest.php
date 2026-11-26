<?php

use PHPUnit\Framework\TestCase;

/**
 * Parses the sources with the tokenizer instead of loading them, so the
 * check does not depend on the Cake bootstrap.
 */
class DeletedEventRecoveryRemovedTest extends TestCase
{
    private const REMOVED_ACTIONS = ['recoverEvent', 'restoreDeletedEvents'];

    private function source($relative)
    {
        $path = __DIR__ . '/../' . $relative;
        $this->assertFileExists($path);
        return file_get_contents($path);
    }

    private function methods($relative)
    {
        $tokens = token_get_all($this->source($relative));
        $names = [];
        foreach ($tokens as $i => $token) {
            if (!is_array($token) || $token[0] !== T_FUNCTION) {
                continue;
            }
            for ($j = $i + 1; $j < count($tokens); $j++) {
                if (is_array($tokens[$j]) && $tokens[$j][0] === T_STRING) {
                    $names[] = $tokens[$j][1];
                    break;
                }
                if (!is_array($tokens[$j]) && $tokens[$j] !== '&') {
                    break;
                }
            }
        }
        return $names;
    }

    private function aclActions()
    {
        $tokens = token_get_all($this->source('Controller/Component/ACLComponent.php'));
        $keys = [];
        foreach ($tokens as $i => $token) {
            if (is_array($token) && $token[0] === T_CONSTANT_ENCAPSED_STRING) {
                $keys[] = trim($token[1], '\'"');
            }
        }
        return $keys;
    }

    public function testAclListsNoRecoveryActions()
    {
        $keys = $this->aclActions();
        $this->assertContains('runTaxonomyExclusivityCheck', $keys);
        foreach (self::REMOVED_ACTIONS as $action) {
            $this->assertNotContains($action, $keys);
        }
    }

    public function testEventsControllerHasNoRecoveryActions()
    {
        $methods = $this->methods('Controller/EventsController.php');
        $this->assertContains('runTaxonomyExclusivityCheck', $methods);
        foreach (self::REMOVED_ACTIONS as $action) {
            $this->assertNotContains($action, $methods);
        }
    }

    public function testEventModelAndShellHaveNoRecoveryEntryPoints()
    {
        $this->assertNotContains('recoverEvent', $this->methods('Model/Event.php'));
        $shell = $this->methods('Console/Command/EventShell.php');
        $this->assertContains('testEventNotificationEmail', $shell);
        $this->assertNotContains('recoverEvent', $shell);
    }

    public function testLogModelHasNoRecoveryCode()
    {
        $methods = $this->methods('Model/Log.php');
        $this->assertContains('createLogEntry', $methods);
        foreach ($methods as $method) {
            $this->assertNotRegExp(
                '/^(findDeletedEvents|changeParser|recoverDeleted\w*|__recoverDeleted\w*|__executeRecovery\w*)$/',
                $method
            );
        }
    }

    public function testRecoveryViewsAreGone()
    {
        $this->assertFalse(file_exists(__DIR__ . '/../View/Events/recover_event.ctp'));
        $this->assertFalse(file_exists(__DIR__ . '/../View/Events/restore_deleted_events.ctp'));
    }

    public function testNoTemplateLinksToRecoveryActions()
    {
        $views = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(__DIR__ . '/../View'));
        foreach ($views as $file) {
            if (substr($file->getFilename(), -4) !== '.ctp') {
                continue;
            }
            $content = file_get_contents($file->getPathname());
            $this->assertFalse(strpos($content, 'restoreDeletedEvents') !== false, $file->getPathname());
            $this->assertFalse(strpos($content, 'restore_deleted_events') !== false, $file->getPathname());
            $this->assertFalse(strpos($content, 'events/recoverEvent') !== false, $file->getPathname());
        }
    }
}
