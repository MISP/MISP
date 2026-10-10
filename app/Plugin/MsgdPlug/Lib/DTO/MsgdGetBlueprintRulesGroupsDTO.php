<?php

/**
 * MsgdPlug Plugin
 *
 * @author     TETRAPI SA, Lino Pacheco
 * @license    AGPL-3.0
 */

declare(strict_types=1);

/**
 * Request object for resolving Blueprint groups.
 *
 * @package    MsgdPlug
 * @subpackage MsgdPlug.Lib.DTO
 */
final class MsgdGetBlueprintRulesGroupsDTO
{
    /**
     * Allowed query parameters.
     *
     * @var array<int, string>
     */
    private const ALLOWED_FIELDS = ['group'];

    /**
     * Validated group integer ID.
     *
     * @var int
     */
    public readonly int $group;

    /**
     * Creates and validates a request instance from query parameters.
     *
     * @param array<string, mixed> $rawQueryParams
     *
     * @throws InvalidArgumentException
     */
    public function __construct(array $rawQueryParams = [])
    {
        /** @var array<string, mixed> $payload */
        $payload = isset($rawQueryParams['MsgdPlug']) && is_array($rawQueryParams['MsgdPlug'])
            ? $rawQueryParams['MsgdPlug']
            : $rawQueryParams;

        unset($payload['url'], $payload['_']);

        $unauthorizedFields = array_diff(array_keys($payload), self::ALLOWED_FIELDS);

        if (!empty($unauthorizedFields)) {
            $sanitizedUnauthorizedFields = array_map(
                static fn(int|string $field): string => MsgdSanitizerUtility::sanitizeString((string)$field, 64),
                $unauthorizedFields
            );

            throw new InvalidArgumentException(
                sprintf(
                    'Unauthorized parameters detected in query: [%s].',
                    implode(', ', $sanitizedUnauthorizedFields)
                )
            );
        }

        if (!array_key_exists('group', $payload) || $payload['group'] === '') {
            throw new InvalidArgumentException('Query parameter "group" is required and cannot be empty.');
        }

        $rawGroup = $payload['group'];

        if (!is_int($rawGroup) && !is_string($rawGroup)) {
            throw new InvalidArgumentException('Query parameter "group" must be a positive integer.');
        }

        if (!preg_match('/^[1-9][0-9]*$/', (string)$rawGroup)) {
            throw new InvalidArgumentException('Query parameter "group" must be a positive integer.');
        }

        $group = filter_var($rawGroup, FILTER_VALIDATE_INT, [
            'options' => ['min_range' => 1],
        ]);

        if ($group === false) {
            throw new InvalidArgumentException('Query parameter "group" must be a valid positive integer.');
        }

        $this->group = $group;
    }
}
