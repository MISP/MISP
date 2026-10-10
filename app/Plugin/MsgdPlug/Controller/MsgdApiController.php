<?php

/**
 * MsgdPlug Plugin
 *
 * @author     TETRAPI SA, Lino Pacheco
 * @license    AGPL-3.0
 */

declare(strict_types=1);

App::uses('MsgdPlugAppController', 'MsgdPlug.Controller');

/**
 * Main API controller for blueprint and sharing group operations.
 *
 * @api
 * @apiController
 *
 * @package    MsgdPlug
 * @subpackage MsgdPlug.Controller
 */
class MsgdApiController extends MsgdPlugAppController
{
    private MsgdApiControllerService $msgdService;
    private MsgdSharingGroupVoter $voter;

    /**
     * Initializes services and configures endpoint security rules.
     *
     * @return void
     */
    public function beforeFilter(): void
    {
        parent::beforeFilter();
        $this->voter = new MsgdSharingGroupVoter();
        $this->msgdService = new MsgdApiControllerService(voter: $this->voter);
    }

    /**
     * Checks if the current user has the required sharing group permission.
     *
     * @return CakeResponse JSON response containing the user's permission status.
     *
     * @api
     *
     * @route GET /msgd-plug/msgd-api/check-user-permission
     */
    public function checkUserPermission(): CakeResponse
    {
        $this->request->allowMethod(['get']);

        if (!$this->validateRequest()) {
            return $this->buildJsonResponse([
                'status' => 'error',
                'message' => 'Unauthorized access.',
            ], 403);
        }

        try {
            $user = $this->getCurrentUser();
            if ($user === null) {
                return $this->buildJsonResponse(['status' => 'error', 'message' => 'Unauthorized'], 401);
            }

            $allowed = $this->voter->vote($user, MsgdSharingGroupVoter::USE_SHARING_GROUPS);

            return $this->buildJsonResponse([
                'status' => 'success',
                'allowed' => $allowed,
            ]);
        } catch (Throwable $exception) {
            MsgdLoggerUtility::logException($exception, '[MsgdApiController] checkUserPermission failed');

            return $this->buildJsonResponse([
                'status' => 'error',
                'allowed' => false,
                'message' => 'Failed to verify user permissions.',
            ], 500);
        }
    }

    /**
     * Fetches sharing groups linked to a specific blueprint.
     *
     * @return CakeResponse JSON response containing the resolved sharing groups.
     *
     * @api
     *
     * @route GET /msgd-plug/msgd-api/get-blueprint-rules-groups
     *
     * @apiQuery {int} [group]
     * Blueprint group ID used to retrieve associated sharing groups.
     */
    public function getBlueprintRulesGroups(): CakeResponse
    {
        $this->request->allowMethod(['get']);

        if (!$this->validateRequest()) {
            return $this->buildJsonResponse([
                'status' => 'error',
                'message' => 'Unauthorized access.',
            ], 403);
        }

        try {
            $user = $this->getCurrentUser();
            if ($user === null) {
                return $this->buildJsonResponse(['status' => 'error', 'message' => 'Unauthorized'], 401);
            }
            /** @var array<string, mixed> $query */
            $query = $this->request->query;
            $requestData = new MsgdGetBlueprintRulesGroupsDTO($query);
            $groups = $this->msgdService->getSharingGroupsByGeneratedBlueprintGroup($user, $requestData->group);

            return $this->buildJsonResponse([
                'status' => 'success',
                'groups' => $groups,
            ]);
        } catch (InvalidArgumentException) {
            return $this->buildJsonResponse([
                'status' => 'error',
                'message' => 'Invalid parameters provided for blueprint rules.',
            ], 400);
        } catch (Throwable $exception) {
            MsgdLoggerUtility::logException($exception, '[MsgdApiController] getBlueprintRulesGroups failed');

            return $this->buildJsonResponse([
                'status' => 'error',
                'message' => 'Failed to resolve blueprint sharing groups.',
            ], 500);
        }
    }

    /**
     * Fetches available sharing groups for the current session.
     *
     * @return CakeResponse JSON response containing available sharing groups.
     *
     * @api
     *
     * @route GET /msgd-plug/msgd-api/get-sharing-groups
     *
     * @apiQuery {bool} [all]
     * If true, returns all sharing groups; otherwise, returns only
     * sharing groups not created by blueprints.
     */
    public function getSharingGroups(): CakeResponse
    {
        $this->request->allowMethod(['get']);

        if (!$this->validateRequest()) {
            return $this->buildJsonResponse([
                'status' => 'error',
                'message' => 'Unauthorized access.',
            ], 403);
        }

        try {
            $user = $this->getCurrentUser();
            if ($user === null) {
                return $this->buildJsonResponse(['status' => 'error', 'message' => 'Unauthorized'], 401);
            }
            /** @var array<string, mixed> $query */
            $query = $this->request->query;
            $requestData = new MsgdGetSharingGroupsDTO($query);
            $groups = $this->msgdService->getAvailableSharingGroups($user, $requestData->all);

            return $this->buildJsonResponse([
                'status' => 'success',
                'groups' => $groups,
            ]);
        } catch (InvalidArgumentException) {
            return $this->buildJsonResponse([
                'status' => 'error',
                'message' => 'Invalid parameters provided for sharing groups.',
            ], 400);
        } catch (Throwable $exception) {
            MsgdLoggerUtility::logException($exception, '[MsgdApiController] getSharingGroups failed');

            return $this->buildJsonResponse([
                'status' => 'error',
                'message' => 'Failed to retrieve sharing groups data.',
            ], 500);
        }
    }

    /**
     * Checks if a blueprint already exists for the given groups.
     *
     * @return CakeResponse JSON response containing the blueprint existence status.
     *
     * @api
     *
     * @route POST /msgd-plug/msgd-api/check-blueprint
     *
     * @apiParam {array<int, int|string>} [groups]
     * List of group IDs or UUIDs to verify blueprint existence for.
     */
    public function checkBlueprint(): CakeResponse
    {
        $this->request->allowMethod(['post']);

        if (!$this->validateRequest()) {
            return $this->buildJsonResponse($this->appendNextToken([
                'status' => 'error',
                'message' => 'Unauthorized access.',
            ]), 403);
        }

        try {
            $user = $this->getCurrentUser();
            if ($user === null) {
                return $this->buildJsonResponse($this->appendNextToken([
                    'status' => 'error',
                    'message' => 'Unauthorized',
                ]), 401);
            }
            /** @var array<string, mixed> $data */
            $data = $this->request->data;
            $requestData = new MsgdCheckBlueprintDTO(
                $data,
                $this->msgdService->isUsingIds()
            );

            $exists = $this->msgdService->isBlueprint($user, $requestData);

            return $this->buildJsonResponse($this->appendNextToken([
                'status' => 'success',
                'exists' => $exists,
            ]));
        } catch (InvalidArgumentException) {
            return $this->buildJsonResponse($this->appendNextToken([
                'status' => 'error',
                'message' => 'Invalid payload format for blueprint verification.',
            ]), 400);
        } catch (ForbiddenException $exception) {
            return $this->buildJsonResponse($this->appendNextToken([
                'status' => 'error',
                'message' => $exception->getMessage(),
            ]), 403);
        } catch (Throwable $exception) {
            MsgdLoggerUtility::logException($exception, '[MsgdApiController] checkBlueprint failed');

            return $this->buildJsonResponse($this->appendNextToken([
                'status' => 'error',
                'message' => 'Failed to verify blueprint existence.',
            ]), 500);
        }
    }

    /**
     * Processes and applies sharing groups and blueprints.
     *
     * @return CakeResponse JSON response containing the processed sharing group.
     *
     * @api
     *
     * @route POST /msgd-plug/msgd-api/process-groups
     *
     * @apiParam {array<int, int|string>} [groups]
     * Array of sharing group IDs or UUIDs to process or combine.
     *
     * @apiParam {string} [customName]
     * Optional custom name for the created blueprint group combination.
     */
    public function processGroups(): CakeResponse
    {
        $this->request->allowMethod(['post']);

        if (!$this->validateRequest()) {
            return $this->buildJsonResponse($this->appendNextToken([
                'status' => 'error',
                'message' => 'Unauthorized access.',
            ]), 403);
        }

        try {
            $user = $this->getCurrentUser();
            if ($user === null) {
                return $this->buildJsonResponse($this->appendNextToken([
                    'status' => 'error',
                    'message' => 'Unauthorized',
                ]), 401);
            }
            /** @var array<string, mixed> $data */
            $data = $this->request->data;
            $requestData = new MsgdProcessGroupsDTO(
                $data,
                $this->msgdService->isUsingIds()
            );

            if (count($requestData->groups) === 1) {
                $result = $this->msgdService->processSingleGroup($user, $requestData->groups[0]);

                if ($result !== null) {
                    return $this->buildJsonResponse($this->appendNextToken([
                        'status' => 'success',
                        'group' => $result,
                    ]));
                }

                return $this->buildJsonResponse($this->appendNextToken([
                    'status' => 'error',
                    'message' => 'Target sharing group could not be found.',
                ]), 404);
            }

            $result = $this->msgdService->processMultiple($user, $requestData);

            return $this->buildJsonResponse($this->appendNextToken([
                'status' => 'success',
                'group' => $result,
            ]));
        } catch (InvalidArgumentException) {
            return $this->buildJsonResponse($this->appendNextToken([
                'status' => 'error',
                'message' => 'Invalid payload format for processing groups.',
            ]), 400);
        } catch (ForbiddenException $exception) {
            return $this->buildJsonResponse($this->appendNextToken([
                'status' => 'error',
                'message' => $exception->getMessage(),
            ]), 403);
        } catch (Throwable $exception) {
            MsgdLoggerUtility::logException($exception, '[MsgdApiController] processGroups failed');

            return $this->buildJsonResponse($this->appendNextToken([
                'status' => 'error',
                'message' => 'System error while processing blueprint.',
            ]), 500);
        }
    }
}
