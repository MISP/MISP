<?php

namespace MispTest\Support;

/**
 * A permissive stand-in for any CakePHP model.
 *
 * MISP modules and widgets resolve collaborators through
 * ClassRegistry::init('Foo') in their constructors and then call arbitrary
 * finder methods on them. A unit test cares about the code under test, not
 * about faithfully reproducing every collaborator, so this returns an empty
 * result for any method and a nested fake for any property.
 *
 * Canned return values can be injected per method:
 *     $fake = new FakeModel(['find' => [['Event' => ['id' => 1]]]]);
 */
class FakeModel implements \ArrayAccess, \Countable, \IteratorAggregate
{
    /**
     * Class constants cannot be produced dynamically, so the few that MISP
     * source reads off a registry-resolved model are declared here.
     */
    const ANALYST_DATA_TYPES = ['Note', 'Opinion', 'Relationship'];

    /** @var array<string,mixed> */
    public $returns = [];
    /** @var array<int,array{0:string,1:array}> every call, for assertions */
    public $calls = [];
    /** @var array<string,mixed> */
    private $props = [];

    public function __construct(array $returns = [])
    {
        $this->returns = $returns;
    }

    public function __call($name, $arguments)
    {
        $this->calls[] = [$name, $arguments];
        if (array_key_exists($name, $this->returns)) {
            $value = $this->returns[$name];
            return $value instanceof \Closure ? $value(...$arguments) : $value;
        }
        return [];
    }

    public static function __callStatic($name, $arguments)
    {
        return [];
    }

    public function __get($name)
    {
        if (!array_key_exists($name, $this->props)) {
            $this->props[$name] = new self();
        }
        return $this->props[$name];
    }

    public function __set($name, $value)
    {
        $this->props[$name] = $value;
    }

    public function __isset($name)
    {
        return true;
    }

    // Some call sites treat a model result as an array.
    #[\ReturnTypeWillChange]
    public function offsetExists($offset) { return true; }
    #[\ReturnTypeWillChange]
    public function offsetGet($offset) { return $this->__get((string)$offset); }
    #[\ReturnTypeWillChange]
    public function offsetSet($offset, $value) { $this->props[(string)$offset] = $value; }
    #[\ReturnTypeWillChange]
    public function offsetUnset($offset) { unset($this->props[(string)$offset]); }
    #[\ReturnTypeWillChange]
    public function count() { return 0; }
    #[\ReturnTypeWillChange]
    public function getIterator() { return new \ArrayIterator([]); }
}
