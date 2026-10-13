<?php

/**
 * MsgdPlug Plugin
 *
 * @author     TETRAPI SA, Lino Pacheco
 * @license    AGPL-3.0
 */

declare(strict_types=1);

/**
 * Request object for blueprint check endpoint.
 *
 * @package    MsgdPlug
 * @subpackage MsgdPlug.Lib.DTO
 */
final class MsgdCheckBlueprintDTO
{
    /**
     * Allowed top-level payload keys.
     *
     * @var array<int, string>
     */
    private const ALLOWED_FIELDS = [
        'groups',
    ];

    /**
     * List of validated group IDs or UUIDs.
     *
     * @var array<int, int|string>
     */
    public array $groups;

    /**
     * Creates and validates a request instance from POST data.
     *
     * @param array<string, mixed> $rawData
     * @param bool $useIds
     *
     * @throws InvalidArgumentException
     */
    public function __construct(array $rawData = [], bool $useIds = false)
    {
        if (!isset($rawData['MsgdPlug']) || !is_array($rawData['MsgdPlug'])) {
            throw new InvalidArgumentException('Payload must be enclosed under the "MsgdPlug" root key.');
        }

        /** @var array<string, mixed> $payload */
        $payload = $rawData['MsgdPlug'];

        $unauthorizedFields = array_diff(array_keys($payload), self::ALLOWED_FIELDS);

        if (!empty($unauthorizedFields)) {
            $sanitizedUnauthorizedFields = array_map(
                static fn(int|string $field): string => MsgdSanitizerUtility::sanitizeString((string)$field, 64),
                $unauthorizedFields
            );

            throw new InvalidArgumentException(
                sprintf(
                    'Unauthorized fields detected in payload: [%s].',
                    implode(', ', $sanitizedUnauthorizedFields)
                )
            );
        }

        $rawGroups = $payload['groups'] ?? null;

        if (!is_array($rawGroups) || empty($rawGroups)) {
            throw new InvalidArgumentException('Field "groups" is required and must be a non-empty array.');
        }

        $groups = [];

        foreach ($rawGroups as $rawGroup) {
            if (!is_scalar($rawGroup)) {
                throw new InvalidArgumentException('Field "groups" contains invalid non-scalar values.');
            }

            $group = trim((string)$rawGroup);

            if ($group === '') {
                throw new InvalidArgumentException('Field "groups" contains empty values.');
            }

            if ($useIds) {
                if (!preg_match('/^[1-9][0-9]*$/', $group)) {
                    throw new InvalidArgumentException('Field "groups" contains invalid integer IDs.');
                }

                $groupId = filter_var($group, FILTER_VALIDATE_INT, [
                    'options' => ['min_range' => 1],
                ]);

                if ($groupId === false) {
                    throw new InvalidArgumentException('Field "groups" contains invalid integer IDs.');
                }

                $groups[] = $groupId;
                continue;
            }

            if (!MsgdSanitizerUtility::isValidUuid($group)) {
                throw new InvalidArgumentException('Field "groups" contains invalid UUIDs.');
            }

            $groups[] = $group;
        }

        $this->groups = $groups;
    }
}
