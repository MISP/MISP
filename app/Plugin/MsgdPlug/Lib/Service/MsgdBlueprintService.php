<?php

/**
 * MsgdPlug Plugin
 *
 * @author     TETRAPI SA, Lino Pacheco
 * @license    AGPL-3.0
 */

declare(strict_types=1);

App::uses('CakeText', 'Utility');
App::uses('ClassRegistry', 'Utility');
App::uses('SharingGroupBlueprint', 'Model');
App::uses('DataSource', 'Model/Datasource');

/**
 * Handles blueprint operations and rules matching for sharing groups.
 *
 * @package    MsgdPlug
 * @subpackage MsgdPlug.Lib.Service
 */
class MsgdBlueprintService
{
    /**
     * MISP SharingGroupBlueprint model instance.
     *
     * @var SharingGroupBlueprint|null
     */
    private ?SharingGroupBlueprint $sharingGroupBlueprint = null;

    /**
     * Initializes model instance.
     *
     * @param SharingGroupBlueprint|null $sharingGroupBlueprint
     *
     * @throws RuntimeException
     */
    public function __construct(?SharingGroupBlueprint $sharingGroupBlueprint = null)
    {
        if ($sharingGroupBlueprint !== null) {
            $this->sharingGroupBlueprint = $sharingGroupBlueprint;
            return;
        }

        $model = ClassRegistry::init(SharingGroupBlueprint::class);

        if ($model instanceof SharingGroupBlueprint) {
            $this->sharingGroupBlueprint = $model;
            return;
        }

        throw new RuntimeException('SharingGroupBlueprint model is unavailable.');
    }

    /**
     * Returns the active model datasource.
     *
     * @return DataSource
     */
    public function getDataSource(): DataSource
    {
        $this->ensureModelAvailable();

        return $this->sharingGroupBlueprint->getDataSource();
    }

    /**
     * Finds a blueprint by its database ID.
     *
     * @param int $id
     *
     * @return MsgdBlueprintDTO|null
     *
     * @throws InvalidArgumentException|RuntimeException
     */
    public function findById(int $id): ?MsgdBlueprintDTO
    {
        $this->ensureModelAvailable();

        try {
            $conditions = ['SharingGroupBlueprint.id' => $id];

            $blueprint = $this->sharingGroupBlueprint->find('first', [
                'conditions' => $conditions,
                'recursive' => -1,
                'callbacks' => false,
            ]);

            if (!is_array($blueprint) || empty($blueprint)) {
                return null;
            }

            /** @var array<string, mixed> $blueprint */
            return new MsgdBlueprintDTO($blueprint);
        } catch (Throwable $exception) {
            MsgdLoggerUtility::logException(
                $exception,
                sprintf('[MsgdBlueprintService] findById failed for ID: %d', $id)
            );

            throw new RuntimeException(
                sprintf(
                    'Database error while retrieving Blueprint ID %d: %s',
                    $id,
                    $exception->getMessage()
                ),
                0,
                $exception
            );
        }
    }

    /**
     * Finds a blueprint directly associated with a specific Sharing Group ID.
     *
     * @param int $sharingGroupId
     *
     * @return MsgdBlueprintDTO|null
     *
     * @throws InvalidArgumentException|RuntimeException
     */
    public function findBySharingGroupId(int $sharingGroupId): ?MsgdBlueprintDTO
    {
        $this->ensureModelAvailable();

        try {
            $conditions = ['SharingGroupBlueprint.sharing_group_id' => $sharingGroupId];

            $blueprint = $this->sharingGroupBlueprint->find('first', [
                'conditions' => $conditions,
                'recursive' => -1,
                'callbacks' => false,
            ]);

            if (!is_array($blueprint) || empty($blueprint)) {
                return null;
            }

            /** @var array<string, mixed> $blueprint */
            return new MsgdBlueprintDTO($blueprint);
        } catch (Throwable $exception) {
            MsgdLoggerUtility::logException(
                $exception,
                sprintf(
                    '[MsgdBlueprintService] findBySharingGroupId failed for ID: %d',
                    $sharingGroupId
                )
            );

            throw new RuntimeException(
                sprintf(
                    'Database error while querying Blueprint for Sharing Group ID %d: %s',
                    $sharingGroupId,
                    $exception->getMessage()
                ),
                0,
                $exception
            );
        }
    }

    /**
     * Finds a blueprint matching an exact set of group UUIDs or IDs.
     *
     * @param MsgdUserDTO $user
     * @param MsgdMirrorGroupsDTO $identifiersMirror
     *
     * @return MsgdBlueprintDTO|null
     *
     * @throws InvalidArgumentException|RuntimeException
     */
    public function findBySharingGroupRules(
        MsgdUserDTO $user,
        MsgdMirrorGroupsDTO $identifiersMirror
    ): ?MsgdBlueprintDTO {
        $this->ensureModelAvailable();

        $idIdentifiersInput = array_map(
            static fn($value): string => (string)$value,
            $identifiersMirror->ids
        );
        sort($idIdentifiersInput, SORT_STRING);

        $uuidIdentifiersInput = array_map(
            static fn($value): string => (string)$value,
            $identifiersMirror->uuids
        );
        sort($uuidIdentifiersInput, SORT_STRING);

        if (empty($idIdentifiersInput) && empty($uuidIdentifiersInput)) {
            return null;
        }

        $queryConditions = [
            'recursive' => -1,
            'conditions' => [],
        ];

        $andConditionsIds = [];

        foreach ($idIdentifiersInput as $identifier) {
            $andConditionsIds[] = [
                'SharingGroupBlueprint.rules LIKE' => '%' . $identifier . '%',
            ];
        }

        $andConditionsUuids = [];

        foreach ($uuidIdentifiersInput as $identifier) {
            $andConditionsUuids[] = [
                'SharingGroupBlueprint.rules LIKE' => '%' . $identifier . '%',
            ];
        }

        $orConditions = [];

        if (!empty($andConditionsIds)) {
            $orConditions[] = ['AND' => $andConditionsIds];
        }

        if (!empty($andConditionsUuids)) {
            $orConditions[] = ['AND' => $andConditionsUuids];
        }

        $queryConditions['conditions']['OR'] = $orConditions;

        try {
            $blueprints = $this->sharingGroupBlueprint->find('all', $queryConditions);

            if (!is_array($blueprints)) {
                return null;
            }

            foreach ($blueprints as $blueprintData) {
                if (!is_array($blueprintData)) {
                    continue;
                }

                /** @var array<string, mixed> $blueprintData */
                $blueprint = new MsgdBlueprintDTO($blueprintData);
                $extractedIdentifiers = $blueprint->rules->allSharingGroupIdentifiers;

                if (empty($extractedIdentifiers)) {
                    continue;
                }

                $normalizedExtracted = array_map(
                    static fn($identifier): string => (string)$identifier,
                    $extractedIdentifiers
                );
                sort($normalizedExtracted, SORT_STRING);

                $matchesPrimary = !empty($idIdentifiersInput)
                    && $idIdentifiersInput === $normalizedExtracted;

                $matchesMirror = !empty($uuidIdentifiersInput)
                    && $uuidIdentifiersInput === $normalizedExtracted;

                if ($matchesPrimary || $matchesMirror) {
                    if (!$blueprint->sharingGroupId) {
                        if (($blueprint->orgId === $user->orgId) || ($user->isSiteAdmin)) {
                            return $blueprint;
                        }
                    } else {
                        return $blueprint;
                    }
                }
            }

            return null;
        } catch (Throwable $exception) {
            MsgdLoggerUtility::logException(
                $exception,
                '[MsgdBlueprintService] findBySharingGroupRules'
            );

            throw new RuntimeException(
                'Database error while finding Blueprint by Sharing Group rules: '
                . $exception->getMessage(),
                0,
                $exception
            );
        }
    }

    /**
     * Retrieves all sharing group IDs currently associated with an active blueprint.
     *
     * @return array<int, int>
     *
     * @throws RuntimeException
     */
    public function getGeneratedGroups(): array
    {
        $this->ensureModelAvailable();

        try {
            $rawIds = $this->sharingGroupBlueprint->find('list', [
                'fields' => ['SharingGroupBlueprint.sharing_group_id'],
                'conditions' => [
                    'SharingGroupBlueprint.sharing_group_id >' => 0,
                ],
                'recursive' => -1,
                'callbacks' => false,
            ]);

            if (!is_array($rawIds)) {
                return [];
            }

            $ids = [];
            foreach ($rawIds as $rawId) {
                if (is_numeric($rawId)) {
                    $id = (int)$rawId;
                    if ($id > 0) {
                        $ids[] = $id;
                    }
                }
            }

            return array_values(array_unique($ids));
        } catch (Throwable $exception) {
            MsgdLoggerUtility::logException(
                $exception,
                '[MsgdBlueprintService] getGeneratedGroups'
            );

            throw new RuntimeException(
                'Database error while fetching associated Sharing Group IDs: '
                . $exception->getMessage(),
                0,
                $exception
            );
        }
    }

    /**
     * Resets a blueprint's sharing group reference back to zero.
     *
     * @param MsgdUserDTO $user
     * @param MsgdBlueprintDTO $blueprint
     * @param string|null $name
     *
     * @return bool
     *
     * @throws RuntimeException|JsonException|InvalidArgumentException
     */
    public function resetSharingGroupRef(
        MsgdUserDTO $user,
        MsgdBlueprintDTO $blueprint,
        ?string $name = null
    ): bool {
        $this->ensureModelAvailable();

        $blueprint->sharingGroupId = 0;

        if ($name !== null && trim($name) !== '') {
            $sanitizedName = MsgdSanitizerUtility::sanitizeString($name);

            if ($sanitizedName !== '') {
                $blueprint->name = $sanitizedName;
            }
        }

        if (
            !$this->sharingGroupBlueprint->validateBlueprintPermissions(
                $blueprint->toModelArray(),
                $user->toModelArray()
            )
        ) {
            throw new MethodNotAllowedException('You are not allowed to modify the target sharing group.');
        }

        try {
            $this->sharingGroupBlueprint->create(false);

            if (!$this->sharingGroupBlueprint->save($blueprint->toModelArray())) {
                $validationErrors = $this->sharingGroupBlueprint->validationErrors ?? [];
                $formattedErrors = json_encode($validationErrors) ?: '[]';

                throw new RuntimeException(
                    sprintf(
                        'Database validation failed while repairing Blueprint ID %d: %s',
                        $blueprint->id,
                        $formattedErrors
                    )
                );
            }

            return true;
        } catch (Throwable $exception) {
            if (
                $exception instanceof RuntimeException
                || $exception instanceof InvalidArgumentException
            ) {
                throw $exception;
            }

            MsgdLoggerUtility::logException(
                $exception,
                sprintf(
                    '[MsgdBlueprintService] repair for ID: %d',
                    $blueprint->id
                )
            );

            throw new RuntimeException(
                sprintf(
                    'Failed to repair Blueprint ID %d due to DB error: %s',
                    $blueprint->id,
                    $exception->getMessage()
                ),
                0,
                $exception
            );
        }
    }

    /**
     * Creates a new blueprint with the given UUID/ID rules.
     *
     * @param MsgdUserDTO $user
     * @param MsgdProcessGroupsDTO $payload
     *
     * @return int
     *
     * @throws RuntimeException|JsonException|InvalidArgumentException
     */
    public function create(
        MsgdUserDTO $user,
        MsgdProcessGroupsDTO $payload
    ): int {
        $this->ensureModelAvailable();

        $sanitizedName = trim($payload->customName) !== ''
            ? MsgdSanitizerUtility::sanitizeString($payload->customName)
            : '';

        $blueprintName = $sanitizedName !== ''
            ? $sanitizedName
            : 'MsgdPlug Blueprint - ' . date('Y-m-d H:i:s');

        $newBlueprint = new MsgdBlueprintDTO([
            'id' => 0,
            'uuid' => CakeText::uuid(),
            'name' => $blueprintName,
            'user_id' => $user->id,
            'org_id' => $user->orgId,
            'sharing_group_id' => 0,
            'rules' => MsgdBlueprintRulesDTO::generateFromIdentifiers($payload->groups),
        ]);

        if (
            !$this->sharingGroupBlueprint->validateBlueprintPermissions(
                $newBlueprint->toModelArray(),
                $user->toModelArray()
            )
        ) {
            throw new MethodNotAllowedException(
                'You are not allowed to modify the target sharing group.'
            );
        }

        try {
            $this->sharingGroupBlueprint->create(false);

            if ($this->sharingGroupBlueprint->save($newBlueprint->toModelArray())) {
                $rawId = $this->sharingGroupBlueprint->id;
                return is_numeric($rawId) ? (int)$rawId : 0;
            }

            $validationErrors = $this->sharingGroupBlueprint->validationErrors ?? [];
            $formattedErrors = json_encode($validationErrors) ?: '[]';

            throw new RuntimeException(
                'DB rejected creation of new Blueprint. Errors: '
                . $formattedErrors
            );
        } catch (Throwable $exception) {
            if (
                $exception instanceof RuntimeException
                || $exception instanceof InvalidArgumentException
            ) {
                throw $exception;
            }

            MsgdLoggerUtility::logException(
                $exception,
                '[MsgdBlueprintService] create'
            );

            throw new RuntimeException(
                'Failed to create Blueprint: ' . $exception->getMessage(),
                0,
                $exception
            );
        }
    }

    /**
     * Runs the blueprint engine to generate a sharing group.
     *
     * @param int $id
     *
     * @return int
     *
     * @throws InvalidArgumentException|RuntimeException
     */
    public function execute(int $id): int
    {
        $this->ensureModelAvailable();

        $blueprintRecordBefore = $this->findById($id);

        if (!$blueprintRecordBefore instanceof MsgdBlueprintDTO) {
            throw new RuntimeException(
                sprintf('Cannot execute Blueprint ID %d: Record not found or not accessible.', $id)
            );
        }

        try {
            $this->sharingGroupBlueprint->execute([
                $blueprintRecordBefore->toModelArray(),
            ]);
        } catch (Throwable $exception) {
            MsgdLoggerUtility::logException(
                $exception,
                sprintf('[MsgdBlueprintService] MISP execute() failed for ID %d', $id)
            );

            throw new RuntimeException(
                sprintf(
                    'Native MISP execute() failed for Blueprint ID %d: %s',
                    $id,
                    $exception->getMessage()
                ),
                0,
                $exception
            );
        }

        $blueprintRecordAfter = $this->findById($id);

        if (!$blueprintRecordAfter instanceof MsgdBlueprintDTO) {
            throw new RuntimeException(
                sprintf('Cannot execute Blueprint ID %d: Record not found or not accessible.', $id)
            );
        }

        $sharingGroupId = $blueprintRecordAfter->sharingGroupId;

        if ($sharingGroupId <= 0) {
            throw new RuntimeException(
                sprintf(
                    'MISP engine executed but failed to assign a valid Sharing Group ID to Blueprint %d.',
                    $id
                )
            );
        }

        return $sharingGroupId;
    }

    /**
     * Helper method to ensure the model dependency is present.
     *
     * @throws RuntimeException
     * @phpstan-assert SharingGroupBlueprint $this->sharingGroupBlueprint
     */
    private function ensureModelAvailable(): void
    {
        if ($this->sharingGroupBlueprint === null) {
            throw new RuntimeException('SharingGroupBlueprint model is unavailable.');
        }
    }
}
