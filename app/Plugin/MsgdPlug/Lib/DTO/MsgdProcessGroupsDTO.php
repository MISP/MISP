<?php

/**
 * MsgdPlug Plugin
 *
 * @author     TETRAPI SA, Lino Pacheco
 * @license    AGPL-3.0
 */

declare(strict_types=1);

/**
 * Request object for adding new combination blueprints.
 *
 * @package    MsgdPlug
 * @subpackage MsgdPlug.Lib.DTO
 */
final class MsgdProcessGroupsDTO
{
    /**
     * Allowed top-level payload keys.
     *
     * @var array<int, string>
     */
    private const ALLOWED_FIELDS = ['groups', 'customName'];

    /**
     * @var array<int, int|string>
     */
    public readonly array $groups;

    /**
     * @var string
     */
    public readonly string $customName;

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
                    'Unauthorized fields in MsgdPlug payload: [%s].',
                    implode(', ', $sanitizedUnauthorizedFields)
                )
            );
        }

        $rawGroups = $payload['groups'] ?? [];

        if (!is_array($rawGroups) || empty($rawGroups)) {
            throw new InvalidArgumentException('Field "groups" is required and must be an array.');
        }

        $sanitizedGroups = [];

        foreach ($rawGroups as $rawGroup) {
            if (!is_scalar($rawGroup)) {
                throw new InvalidArgumentException('Field "groups" contains invalid non-scalar values.');
            }

            $sanitizedGroup = MsgdSanitizerUtility::sanitizeString((string)$rawGroup);

            if ($useIds) {
                if (!preg_match('/^[1-9][0-9]*$/', $sanitizedGroup)) {
                    throw new InvalidArgumentException('Field "groups" contains invalid integer IDs.');
                }

                $groupId = filter_var($sanitizedGroup, FILTER_VALIDATE_INT, [
                    'options' => ['min_range' => 1],
                ]);

                if ($groupId === false) {
                    throw new InvalidArgumentException('Field "groups" contains invalid integer IDs.');
                }

                $sanitizedGroups[] = $groupId;
                continue;
            }

            if (!MsgdSanitizerUtility::isValidUuid($sanitizedGroup)) {
                throw new InvalidArgumentException('Field "groups" contains invalid UUIDs.');
            }

            $sanitizedGroups[] = $sanitizedGroup;
        }

        $rawCustomName = $payload['customName'] ?? null;
        $sanitizedCustomName = '';

        if ($rawCustomName !== null && $rawCustomName !== '') {
            if (!is_scalar($rawCustomName)) {
                throw new InvalidArgumentException('Field "customName" must be a scalar value.');
            }

            $trimmedCustomName = trim((string)$rawCustomName);

            if (mb_strlen($trimmedCustomName, 'UTF-8') > MsgdSanitizerUtility::MAX_NAME_LENGTH) {
                throw new InvalidArgumentException(
                    sprintf(
                        'Field "customName" cannot exceed %d characters.',
                        MsgdSanitizerUtility::MAX_NAME_LENGTH
                    )
                );
            }

            $sanitizedCustomName = MsgdSanitizerUtility::sanitizeString($trimmedCustomName);

            if ($sanitizedCustomName === '') {
                throw new InvalidArgumentException('Field "customName" cannot be empty when provided.');
            }
        }

        $this->groups = $sanitizedGroups;
        $this->customName = $sanitizedCustomName;
    }
}
