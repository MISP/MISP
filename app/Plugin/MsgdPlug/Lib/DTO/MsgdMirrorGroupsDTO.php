<?php

/**
 * MsgdPlug Plugin
 *
 * @author     TETRAPI SA, Lino Pacheco
 * @license    AGPL-3.0
 */

declare(strict_types=1);

/**
 * Represents resolved mirror Sharing Group identifiers.
 *
 * @package    MsgdPlug
 * @subpackage MsgdPlug.Lib.DTO
 */
final class MsgdMirrorGroupsDTO
{
    /**
     * @var array<int, int>
     */
    public readonly array $ids;

    /**
     * @var array<int, string>
     */
    public readonly array $uuids;

    /**
     * Creates a DTO from resolved Sharing Group identifiers.
     *
     * @param array<int, int> $ids
     * @param array<int, string> $uuids
     */
    public function __construct(
        array $ids = [],
        array $uuids = []
    ) {
        $this->ids = array_values(array_unique($ids));
        $this->uuids = array_values(array_unique($uuids));
    }
}
