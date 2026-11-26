<?php

/**
 * MsgdPlug Plugin
 *
 * @author     TETRAPI SA, Lino Pacheco
 * @license    AGPL-3.0
 */

declare(strict_types=1);

/**
 * Service for sharing group and blueprint operations.
 *
 * @package    MsgdPlug
 * @subpackage MsgdPlug.Lib.Service
 */
class MsgdApiControllerService
{
    /**
     * @var MsgdSharingGroupService
     */
    private MsgdSharingGroupService $sgLib;

    /**
     * @var MsgdBlueprintService
     */
    private MsgdBlueprintService $bpLib;

    /**
     * @var MsgdSharingGroupVoter
     */
    private MsgdSharingGroupVoter $voter;

    /**
     * Initializes service dependencies.
     *
     * @param MsgdSharingGroupService|null $sgLib
     * @param MsgdBlueprintService|null $bpLib
     * @param MsgdSharingGroupVoter|null $voter
     */
    public function __construct(
        ?MsgdSharingGroupService $sgLib = null,
        ?MsgdBlueprintService $bpLib = null,
        ?MsgdSharingGroupVoter $voter = null
    ) {
        $this->sgLib = $sgLib ?? new MsgdSharingGroupService();
        $this->bpLib = $bpLib ?? new MsgdBlueprintService();
        $this->voter = $voter ?? new MsgdSharingGroupVoter();
    }

    /**
     * Returns whether the plugin is configured to use numeric IDs.
     *
     * @return bool True if numeric IDs are configured, false if UUIDs are used.
     */
    public function isUsingIds(): bool
    {
        return (bool)Configure::read(MsgdPluginConfigEnum::user_ids->value);
    }

    /**
     * Resolves sharing groups linked to a blueprint associated with a target group.
     *
     * @param MsgdUserDTO $user
     * @param int $sharingGroupId
     *
     * @return array<int, MsgdSharingGroupDTO>
     *
     * @throws RuntimeException|InvalidArgumentException
     */
    public function getSharingGroupsByGeneratedBlueprintGroup(
        MsgdUserDTO $user,
        int $sharingGroupId
    ): array {
        $targetSharingGroup = $this->sgLib->findById($user, $sharingGroupId);

        if (!$targetSharingGroup instanceof MsgdSharingGroupDTO) {
            return [];
        }

        $matchedBlueprint = $this->bpLib->findBySharingGroupId($sharingGroupId);

        if ($matchedBlueprint instanceof MsgdBlueprintDTO) {
            if (empty($matchedBlueprint->rules->allSharingGroupIdentifiers)) {
                return [];
            }

            $uuids = $matchedBlueprint->rules->sharingGroupsUuids;
            $ids = $matchedBlueprint->rules->sharingGroupsIds;
        } else {
            $ids = [$targetSharingGroup->id];
            $uuids = [];
        }

        $queryConditions = [];

        if (!empty($uuids) && !empty($ids)) {
            $queryConditions['OR'] = [
                'SharingGroup.uuid' => $uuids,
                'SharingGroup.id' => $ids,
            ];
        } elseif (!empty($uuids)) {
            $queryConditions['SharingGroup.uuid'] = $uuids;
        } else {
            $queryConditions['SharingGroup.id'] = $ids;
        }

        return $this->sgLib->getList($user, $queryConditions);
    }

    /**
     * Retrieves available sharing groups.
     *
     * @param MsgdUserDTO $user
     * @param bool $all If false, ignore blueprint generated groups.
     *
     * @return array<int, MsgdSharingGroupDTO>
     *
     * @throws RuntimeException
     */
    public function getAvailableSharingGroups(MsgdUserDTO $user, bool $all = false): array
    {
        $queryConditions = [];

        if (!$all) {
            $excludedSharingGroupIds = $this->bpLib->getGeneratedGroups();

            if (!empty($excludedSharingGroupIds)) {
                $queryConditions['NOT'] = ['SharingGroup.id' => $excludedSharingGroupIds];
            }
        }

        return $this->sgLib->getList($user, $queryConditions);
    }

    /**
     * Resolves a single sharing group details by UUID or ID.
     *
     * @param MsgdUserDTO $user
     * @param string|int $identifier
     *
     * @return MsgdProcessResultDTO|null
     *
     * @throws RuntimeException|InvalidArgumentException
     */
    public function processSingleGroup(MsgdUserDTO $user, string|int $identifier): ?MsgdProcessResultDTO
    {
        if (MsgdSanitizerUtility::isValidUuid((string)$identifier)) {
            $targetSharingGroup = $this->sgLib->findByUuid($user, (string)$identifier);
        } elseif (is_numeric($identifier) && (int)$identifier > 0) {
            $targetSharingGroup = $this->sgLib->findById($user, (int)$identifier);
        } else {
            return null;
        }

        if ($targetSharingGroup instanceof MsgdSharingGroupDTO) {
            return new MsgdProcessResultDTO(
                [
                        'is_new' => false,
                        'has_blueprint' => false,
                        'sharing_group_id' => $targetSharingGroup->id,
                        'sharing_group_name' => MsgdSanitizerUtility::sanitizeString($targetSharingGroup->name),
                ]
            );
        }

        return null;
    }

    /**
     * Checks if a blueprint already exists matching the given UUID/ID set.
     *
     * @param MsgdUserDTO $user
     * @param MsgdCheckBlueprintDTO $payload
     *
     * @return bool
     *
     * @throws InvalidArgumentException|RuntimeException
     */
    public function isBlueprint(MsgdUserDTO $user, MsgdCheckBlueprintDTO $payload): bool
    {
        $mirrors = $this->sgLib->getMirrorGroups($user, $payload->groups);

        if (empty($mirrors)) {
            return false;
        }

        return $this->bpLib->findBySharingGroupRules($user, $mirrors) !== null;
    }

    /**
     * Orchestrates blueprint creation, repair, and execution.
     *
     * @param MsgdUserDTO $user
     * @param MsgdProcessGroupsDTO $payload
     *
     * @return MsgdProcessResultDTO
     *
     * @throws RuntimeException|InvalidArgumentException|Throwable|ForbiddenException
     */
    public function processMultiple(
        MsgdUserDTO $user,
        MsgdProcessGroupsDTO $payload
    ): MsgdProcessResultDTO {
        $mirrors = $this->sgLib->getMirrorGroups($user, $payload->groups);
        $matchedExistingBlueprint = $mirrors !== null
            ? $this->bpLib->findBySharingGroupRules($user, $mirrors)
            : null;

        $isNew = true;
        $associatedSharingGroupId = 0;
        $executedSharingGroupId = null;

        $databaseTransaction = $this->bpLib->getDataSource();

        $databaseTransaction->begin();

        try {
            if ($matchedExistingBlueprint !== null) {
                $targetBlueprintId = $matchedExistingBlueprint->id;
                $associatedSharingGroupId = $matchedExistingBlueprint->sharingGroupId;
                $associatedSharingGroupRecord = $this->sgLib->findById($user, $associatedSharingGroupId);

                if (!$associatedSharingGroupRecord instanceof MsgdSharingGroupDTO) {
                    $this->voter->denyAccessUnlessGranted(
                        $user,
                        MsgdSharingGroupVoter::USE_SHARING_GROUPS
                    );

                    $this->bpLib->resetSharingGroupRef($user, $matchedExistingBlueprint, $payload->customName);
                } else {
                    $isNew = false;
                }
            } else {
                $this->voter->denyAccessUnlessGranted(
                    $user,
                    MsgdSharingGroupVoter::USE_SHARING_GROUPS
                );

                $targetBlueprintId = $this->bpLib->create($user, $payload);
            }

            if ($this->voter->vote($user, MsgdSharingGroupVoter::USE_SHARING_GROUPS)) {
                $executedSharingGroupId = $this->bpLib->execute($targetBlueprintId);
            }

            $targetGroupIdToFetch = $executedSharingGroupId ?? $associatedSharingGroupId;
            $updatedSharingGroupRecord = $targetGroupIdToFetch > 0
                ? $this->sgLib->findById($user, $targetGroupIdToFetch)
                : null;

            if (!$updatedSharingGroupRecord instanceof MsgdSharingGroupDTO) {
                throw new RuntimeException(
                    'Blueprint execution or lookup returned an invalid ID, Sharing Group record not found.'
                );
            }

            $databaseTransaction->commit();

            return new MsgdProcessResultDTO(
                [
                        'is_new' => $isNew,
                        'has_blueprint' => true,
                        'sharing_group_id' => $updatedSharingGroupRecord->id,
                        'sharing_group_name' => $updatedSharingGroupRecord->name,
                ]
            );
        } catch (Throwable $exception) {
            $databaseTransaction->rollback();
            MsgdLoggerUtility::logException(
                $exception,
                '[MsgdPlug Service: processMultiple] Transaction failed'
            );
            throw $exception;
        }
    }
}
