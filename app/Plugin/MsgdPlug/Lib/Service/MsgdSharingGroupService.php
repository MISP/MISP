<?php

/**
 * MsgdPlug Plugin
 *
 * @author     TETRAPI SA, Lino Pacheco
 * @license    AGPL-3.0
 */

declare(strict_types=1);

App::uses('SharingGroup', 'Model');
App::uses('ClassRegistry', 'Utility');
App::uses('DataSource', 'Model/Datasource');

/**
 * Handles database lookups and queries for MISP sharing groups.
 *
 * @package    MsgdPlug
 * @subpackage MsgdPlug.Lib.Service
 */
class MsgdSharingGroupService
{
    /**
     * MISP SharingGroup model instance.
     *
     * @var SharingGroup|null
     */
    private ?SharingGroup $sharingGroup = null;

    /**
     * Initializes model instance.
     *
     * @param SharingGroup|null $sharingGroup
     *
     * @throws RuntimeException
     */
    public function __construct(?SharingGroup $sharingGroup = null)
    {
        if ($sharingGroup !== null) {
            $this->sharingGroup = $sharingGroup;

            return;
        }

        $model = ClassRegistry::init(SharingGroup::class);

        if ($model instanceof SharingGroup) {
            $this->sharingGroup = $model;

            return;
        }

        throw new RuntimeException('SharingGroup model is unavailable.');
    }

    /**
     * Returns the active model datasource.
     *
     * @return DataSource
     */
    public function getDataSource(): DataSource
    {
        $this->ensureModelAvailable();

        return $this->sharingGroup->getDataSource();
    }


    /**
     * Finds a sharing group by ID.
     *
     * @param MsgdUserDTO $user
     * @param int $id
     *
     * @return MsgdSharingGroupDTO|null
     *
     * @throws RuntimeException|InvalidArgumentException
     */
    public function findById(MsgdUserDTO $user, int $id): ?MsgdSharingGroupDTO
    {
        $this->ensureModelAvailable();
        $mispUser = $user->toModelArray();

        try {
            if (!$this->sharingGroup->checkIfAuthorised($mispUser, $id)) {
                return null;
            }

            $sharingGroup = $this->sharingGroup->find('first', [
                'conditions' => ['SharingGroup.id' => $id],
                'recursive' => -1,
            ]);

            if (!is_array($sharingGroup) || empty($sharingGroup)) {
                return null;
            }

            /** @var array<string, mixed> $sharingGroup */
            return new MsgdSharingGroupDTO($sharingGroup);
        } catch (Throwable $exception) {
            MsgdLoggerUtility::logException(
                $exception,
                sprintf('[MsgdSharingGroupService] findById for ID: %d', $id)
            );

            throw new RuntimeException(
                sprintf(
                    'Database error while retrieving Sharing Group ID %d: %s',
                    $id,
                    $exception->getMessage()
                ),
                0,
                $exception
            );
        }
    }

    /**
     * Finds a sharing group by UUID.
     *
     * @param MsgdUserDTO $user
     * @param string $uuid
     *
     * @return MsgdSharingGroupDTO|null
     *
     * @throws RuntimeException|InvalidArgumentException
     */
    public function findByUuid(MsgdUserDTO $user, string $uuid): ?MsgdSharingGroupDTO
    {
        if (!MsgdSanitizerUtility::isValidUuid($uuid)) {
            throw new InvalidArgumentException(sprintf("Invalid UUID format provided: '%s'.", $uuid));
        }

        $this->ensureModelAvailable();
        $mispUser = $user->toModelArray();

        try {
            if (!$this->sharingGroup->checkIfAuthorised($mispUser, $uuid)) {
                return null;
            }

            $sharingGroup = $this->sharingGroup->find('first', [
                'conditions' => ['SharingGroup.uuid' => $uuid],
                'recursive' => -1,
            ]);

            if (!is_array($sharingGroup) || empty($sharingGroup)) {
                return null;
            }

            /** @var array<string, mixed> $sharingGroup */
            return new MsgdSharingGroupDTO($sharingGroup);
        } catch (Throwable $exception) {
            MsgdLoggerUtility::logException(
                $exception,
                sprintf('[MsgdSharingGroupService] findByUuid for UUID: %s', $uuid)
            );

            throw new RuntimeException(
                sprintf(
                    "Database error while querying Sharing Group by UUID '%s': %s",
                    $uuid,
                    $exception->getMessage()
                ),
                0,
                $exception
            );
        }
    }

    /**
     * Retrieves mirror identifiers (IDs and UUIDs) for a given list of identifiers.
     *
     * @param MsgdUserDTO $user
     * @param array<int, string|int> $identifiers
     *
     * @return MsgdMirrorGroupsDTO|null
     *
     * @throws RuntimeException
     */
    public function getMirrorGroups(MsgdUserDTO $user, array $identifiers): ?MsgdMirrorGroupsDTO
    {
        $this->ensureModelAvailable();

        if (empty($identifiers)) {
            return null;
        }

        $idsToSearch = [];
        $uuidsToSearch = [];

        foreach ($identifiers as $identifier) {
            if (is_numeric($identifier)) {
                $idsToSearch[] = (int)$identifier;
            } elseif (MsgdSanitizerUtility::isValidUuid((string)$identifier)) {
                $uuidsToSearch[] = (string)$identifier;
            }
        }

        if (empty($idsToSearch) && empty($uuidsToSearch)) {
            return null;
        }

        $mispUser = $user->toModelArray();

        try {
            $authorizedIds = $this->sharingGroup->authorizedIds($mispUser);

            if (empty($authorizedIds)) {
                return null;
            }

            $orConditions = [];

            if (!empty($idsToSearch)) {
                $orConditions[] = ['SharingGroup.id' => $idsToSearch];
            }

            if (!empty($uuidsToSearch)) {
                $orConditions[] = ['SharingGroup.uuid' => $uuidsToSearch];
            }

            $retrievedGroups = $this->sharingGroup->find('all', [
                'fields' => ['SharingGroup.id', 'SharingGroup.uuid'],
                'conditions' => [
                    'AND' => [
                        ['SharingGroup.id' => $authorizedIds],
                        ['OR' => $orConditions],
                    ],
                ],
                'recursive' => -1,
            ]);

            if (!is_array($retrievedGroups)) {
                return null;
            }

            $resultIds = [];
            $resultUuids = [];

            foreach ($retrievedGroups as $group) {
                if (!is_array($group) || !isset($group['SharingGroup']) || !is_array($group['SharingGroup'])) {
                    continue;
                }

                $rawId = $group['SharingGroup']['id'] ?? 0;
                if (is_numeric($rawId)) {
                    $resultIds[] = (int)$rawId;
                }

                $rawUuid = $group['SharingGroup']['uuid'] ?? '';
                if (is_scalar($rawUuid) && (string)$rawUuid !== '') {
                    $resultUuids[] = (string)$rawUuid;
                }
            }

            return new MsgdMirrorGroupsDTO($resultIds, $resultUuids);
        } catch (Throwable $exception) {
            MsgdLoggerUtility::logException($exception, '[MsgdSharingGroupService] getMirrorGroups');

            throw new RuntimeException(
                'Database error while fetching mirror groups: ' . $exception->getMessage(),
                0,
                $exception
            );
        }
    }

    /**
     * Returns a list of sharing groups as ID, UUID and name pairs.
     *
     * @param MsgdUserDTO $user
     * @param array<string, mixed> $queryConditions
     *
     * @return array<int, MsgdSharingGroupDTO>
     */
    public function getList(MsgdUserDTO $user, array $queryConditions = []): array
    {
        $this->ensureModelAvailable();
        $mispUser = $user->toModelArray();

        try {
            $authorizedIds = $this->sharingGroup->authorizedIds($mispUser);

            if (empty($authorizedIds)) {
                return [];
            }

            $conditions = [
                'AND' => [
                    ['SharingGroup.id' => $authorizedIds],
                ],
            ];

            if (!empty($queryConditions)) {
                $conditions['AND'][] = $queryConditions;
            }

            $retrievedGroups = $this->sharingGroup->find('all', [
                'fields' => [
                    'SharingGroup.id',
                    'SharingGroup.uuid',
                    'SharingGroup.name',
                ],
                'conditions' => $conditions,
                'order' => ['SharingGroup.name' => 'ASC'],
                'recursive' => -1,
            ]);

            if (!is_array($retrievedGroups) || empty($retrievedGroups)) {
                return [];
            }

            $mappedSharingGroupsList = [];

            foreach ($retrievedGroups as $group) {
                if (!is_array($group)) {
                    continue;
                }

                /** @var array<string, mixed> $group */
                $mappedSharingGroupsList[] = new MsgdSharingGroupDTO($group);
            }

            return $mappedSharingGroupsList;
        } catch (Throwable $exception) {
            MsgdLoggerUtility::logException($exception, '[MsgdSharingGroupService] getList');

            throw new RuntimeException(
                'Database error while fetching Sharing Group list: ' . $exception->getMessage(),
                0,
                $exception
            );
        }
    }

    /**
     * Helper method to ensure the model dependency is present.
     *
     * @phpstan-assert SharingGroup $this->sharingGroup
     *
     * @throws RuntimeException
     */
    private function ensureModelAvailable(): void
    {
        if ($this->sharingGroup === null) {
            throw new RuntimeException('SharingGroup model is unavailable.');
        }
    }
}
