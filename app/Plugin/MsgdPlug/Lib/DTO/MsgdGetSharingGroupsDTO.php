<?php

/**
 * MsgdPlug Plugin
 *
 * @author     TETRAPI SA, Lino Pacheco
 * @license    AGPL-3.0
 */

declare(strict_types=1);

/**
 * Request object for fetching available Sharing Groups.
 *
 * @package    MsgdPlug
 * @subpackage MsgdPlug.Lib.DTO
 */
readonly final class MsgdGetSharingGroupsDTO
{
    /**
     * Allowed query parameters.
     *
     * @var array<int, string>
     */
    private const ALLOWED_FIELDS = ['all'];

    /**
     * Indicates whether to fetch all sharing groups.
     *
     * @var bool
     */
    public bool $all;

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

        $rawAll = $payload['all'] ?? false;

        if (!is_scalar($rawAll)) {
            throw new InvalidArgumentException('Query parameter "all" must be a scalar value.');
        }

        $parsedAll = filter_var($rawAll, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);

        if ($parsedAll === null) {
            throw new InvalidArgumentException('Query parameter "all" must be a valid boolean value.');
        }

        $this->all = $parsedAll;
    }
}
