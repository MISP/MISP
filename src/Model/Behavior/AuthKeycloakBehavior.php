<?php
namespace App\Model\Behavior;

use ArrayObject;
use Cake\Datasource\EntityInterface;
use Cake\Event\EventInterface;
use Cake\ORM\Behavior;
use Cake\ORM\Entity;
use Cake\ORM\Query;
use Cake\Utility\Text;
use Cake\Utility\Security;
use Cake\Utility\Hash;
use \Cake\Http\Session;
use Cake\Core\Configure;
use Cake\Http\Client;
use Cake\Http\Client\FormData;
use Cake\Http\Exception\NotFoundException;

class AuthKeycloakBehavior extends Behavior
{
    public function getUser(EntityInterface $profile, Session $session)
    {
        $userId = $session->read('Auth.User.id');
        if ($userId) {
            return $this->_table->get($userId);
        }

        $raw_profile_payload = $profile->access_token->getJwt()->getPayload();
        $user = $this->extractProfileData($raw_profile_payload);
        if (!$user) {
            throw new \RuntimeException('Unable to authenticate user. The KeyCloak and Cerebrate states of the user differ. This could be due to a missing synchronisation of the data.');
        }

        return $user;
    }

    private function extractProfileData($profile_payload)
    {
        $mapping = Configure::read('keycloak.mapping');
        $fields = [
            'username' => 'preferred_username',
            'email' => 'email',
            'first_name' => 'given_name',
            'last_name' => 'family_name'
        ];
        foreach ($fields as $field => $default) {
            if (!empty($mapping[$field])) {
                $fields[$field] = $mapping[$field];
            }
        }
        $existingUser = $this->_table->find()
            ->where(['username' => $profile_payload[$fields['username']]])
            ->contain('Individuals')
            ->first();
        if ($existingUser['individual']['email'] !== $profile_payload[$fields['email']]) {
            return false;
        }
        return $existingUser;
    }

    /*
     * Run a rest query against keycloak
     * Auto sets the headers and uses a sprintf string to build the URL, injecting the baseurl + realm into the $pathString
     */
    private function restApiRequest(string $pathString, array $payload, string $postRequestType = 'post'): Object
    {
        $token = $this->getAdminAccessToken();
        $keycloakConfig = Configure::read('keycloak');
        $http = new Client();
        $url = sprintf(
            $pathString,
            $keycloakConfig['provider']['baseUrl'],
            $keycloakConfig['provider']['realm']
        );
        return $http->$postRequestType(
            $url,
            json_encode($payload),
            [
                'headers' => [
                    'Content-Type' => 'application/json',
                    'Authorization' => 'Bearer ' . $token
                ]
            ]
        );
    }

    public function getUserIdByUsername(string $username)
    {
        $response = $this->restApiRequest(
            '%s/admin/realms/%s/users/?username=' . urlencode($username),
            [],
            'GET'
        );
        if (!$response->isOk()) {
            $responseBody = json_decode($response->getStringBody(), true);
            $this->_table->auditLogs()->insert([
                'request_action' => 'keycloakGetUser',
                'model' => 'User',
                'model_id' => 0,
                'model_title' => __('Failed to fetch user ({0}) from keycloak', $username),
                'changed' => ['error' => empty($responseBody['errorMessage']) ? 'Unknown error.' : $responseBody['errorMessage']]
            ]);
        }
        $responseBody = json_decode($response->getStringBody(), true);
        if (empty($responseBody[0]['id'])) {
            return false;
        }
        return $responseBody[0]['id'];
    }

    public function deleteUser($data): bool
    {
        $userId = $this->getUserIdByUsername($data['username']);
        if ($userId === false) {
            $this->_table->auditLogs()->insert([
                'request_action' => 'keycloakUserDeletion',
                'model' => 'User',
                'model_id' => 0,
                'model_title' => __('User {0} not found in keycloak, deleting the user locally.', $data['username']),
                'changed' => []
            ]);
            return true;
        }
        $response = $this->restApiRequest(
            '%s/admin/realms/%s/users/' . urlencode($userId),
            [],
            'delete'
        );
        if (!$response->isOk()) {
            $responseBody = json_decode($response->getStringBody(), true);
            $this->_table->auditLogs()->insert([
                'request_action' => 'keycloakUserDeletion',
                'model' => 'User',
                'model_id' => 0,
                'model_title' => __('Failed to delete user {0} ({1}) in keycloak', $data['username'], $userId),
                'changed' => ['error' => empty($responseBody['errorMessage']) ? 'Unknown error.' : $responseBody['errorMessage']]
            ]);
            return false;
        }
        return true;
    }

    public function enrollUser($data): bool
    {
        $roleConditions = [
            'id' => $data['role_id']
        ];
        $user = [
            'username' => $data['username'],
            'disabled' => false,
            'individual' => $this->_table->Individuals->find()->where(
                [
                    'id' => $data['individual_id']
                ]
            )->first(),
            'role' => $this->_table->Roles->find()->where($roleConditions)->first(),
            'organisation' => $this->_table->Organisations->find()->where(
                [
                    'id' => $data['organisation_id']
                ]
            )->first()
        ];
        $clientId = $this->getClientId();
        $newUserId = $this->createUser($user, $clientId);
        if (!$newUserId) {
            $logChange = [
                'username' => $user['username'],
                'individual_id' => $user['individual']['id'],
                'role_id' => $user['role']['id']
            ];
            $this->_table->auditLogs()->insert([
                'request_action' => 'enrollUser',
                'model' => 'User',
                'model_id' => 0,
                'model_title' => __('Failed Keycloak enrollment for user {0}', $user['username']),
                'changed' => $logChange
            ]);
        } else {
            $logChange = [
                'username' => $user['username'],
                'individual_id' => $user['individual']['id'],
                'role_id' => $user['role']['id']
            ];
            $this->_table->auditLogs()->insert([
                'request_action' => 'enrollUser',
                'model' => 'User',
                'model_id' => 0,
                'model_title' => __('Successful Keycloak enrollment for user {0}', $user['username']),
                'changed' => $logChange
            ]);
            $response = $this->restApiRequest(
                '%s/admin/realms/%s/users/' . urlencode($newUserId) . '/execute-actions-email',
                ['UPDATE_PASSWORD'],
                'put'
            );
            if (!$response->isOk()) {
                $responseBody = json_decode($response->getStringBody(), true);
                $this->_table->auditLogs()->insert([
                    'request_action' => 'keycloakWelcomeEmail',
                    'model' => 'User',
                    'model_id' => 0,
                    'model_title' => __('Failed to send welcome mail to user ({0}) in keycloak', $user['username']),
                    'changed' => ['error' => empty($responseBody['errorMessage']) ? 'Unknown error.' : $responseBody['errorMessage']]
                ]);
            }
        }
        return true;
    }

    /**
     * handleUserUpdate
     *
     * @param \App\Model\Entity\User $user
     * @return array Containing changes if successful
     */
    public function handleUserUpdate(\App\Model\Entity\User $user): array
    {
        $user['individual'] = $this->_table->Individuals->find()->where([
            'id' => $user['individual_id']
        ])->first();
        $user['role'] = $this->_table->Roles->find()->where([
             'id' => $user['role_id']
        ])->first();
        $user['organisation'] = $this->_table->Organisations->find()->where([
            'id' => $user['organisation_id']
        ])->first();

        $users = [$user->toArray()];
        $clientId = $this->getClientId();
        $changes = $this->syncUsers($users, $clientId);
        return $changes;
    }

    public function keyCloaklogout(): string
    {
        $keycloakConfig = Configure::read('keycloak');
        $logoutUrl = sprintf(
            '%s/realms/%s/protocol/openid-connect/logout?redirect_uri=%s',
            $keycloakConfig['provider']['baseUrl'],
            $keycloakConfig['provider']['realm'],
            urlencode(Configure::read('App.fullBaseUrl'))
        );
        return $logoutUrl;
    }

    private function getAdminAccessToken()
    {
        $keycloakConfig = Configure::read('keycloak');
        $http = new Client();
        $tokenUrl = sprintf(
            '%s/realms/%s/protocol/openid-connect/token',
            $keycloakConfig['provider']['baseUrl'],
            $keycloakConfig['provider']['realm']
        );
        $response = $http->post(
            $tokenUrl,
            sprintf(
                'grant_type=client_credentials&client_id=%s&client_secret=%s',
                urlencode(Configure::read('keycloak.provider.applicationId')),
                urlencode(Configure::read('keycloak.provider.applicationSecret'))
            ),
            [
                'headers' => [
                    'Content-Type' => 'application/x-www-form-urlencoded'
                ]
            ]
        );
        $parsedResponse = json_decode($response->getStringBody(), true);
        return $parsedResponse['access_token'];
    }

    private function getClientId(): string
    {
        $response = $this->restApiRequest('%s/admin/realms/%s/clients?clientId=' . Configure::read('keycloak.provider.applicationId'), [], 'get');
        $clientId = json_decode($response->getStringBody(), true);
        if (!empty($clientId[0]['id'])) {
            return $clientId[0]['id'];
        } else {
            throw new NotFoundException(__('Keycloak client ID not found or service account doesn\'t have the "view-clients" privilege.'));
        }
    }

    public function syncWithKeycloak(): array
    {
        $this->updateMappers();
        $results = [];
        $data['Users'] = $this->_table->find()->contain(['Individuals', 'Organisations', 'Roles'])->select(
            [
                'id',
                'uuid',
                'username',
                'disabled',
                'Individuals.email',
                'Individuals.first_name',
                'Individuals.last_name',
                'Individuals.uuid',
                'Roles.name',
                'Roles.uuid',
                'Organisations.name',
                'Organisations.uuid'
            ]
        )->disableHydration()->toArray();
        $clientId = $this->getClientId();
        return $this->syncUsers($data['Users'], $clientId);
    }

    private function syncUsers(array $users, $clientId): array
    {
        $response = $this->restApiRequest('%s/admin/realms/%s/users', [], 'get');
        $keycloakUsers = json_decode($response->getStringBody(), true);
        $keycloakUsersParsed = [];
        foreach ($keycloakUsers as $u) {
            $keycloakUsersParsed[$u['username']] = [
                'id' => $u['id'],
                'username' => $u['username'],
                'enabled' => $u['enabled'],
                'firstName' => $u['firstName'],
                'lastName' => $u['lastName'],
                'email' => $u['email'],
                'attributes' => [
                    'role_name' => $u['attributes']['role_name'][0] ?? '',
                    'role_uuid' => $u['attributes']['role_uuid'][0] ?? '',
                    'org_uuid' => $u['attributes']['org_uuid'][0] ?? '',
                    'org_name' => $u['attributes']['org_name'][0] ?? ''
                ]
            ];
        }
        $changes = [
            'created' => [],
            'modified' => [],
        ];
        foreach ($users as &$user) {
            $changed = false;
            if (empty($keycloakUsersParsed[$user['username']])) {
                if ($this->createUser($user, $clientId)) {
                    $changes['created'][] = $user['username'];
                }
            } else {
                if ($this->checkAndUpdateUser($keycloakUsersParsed[$user['username']], $user)) {
                    $changes['modified'][] = $user['username'];
                }
            }
        }
        return $changes;
    }

    private function checkAndUpdateUser(array $keycloakUser, array $user): bool
    {
        if (
            $keycloakUser['enabled'] == $user['disabled'] ||
            $keycloakUser['firstName'] !== $user['individual']['first_name'] ||
            $keycloakUser['lastName'] !== $user['individual']['last_name'] ||
            $keycloakUser['email'] !== $user['individual']['email'] ||
            (empty($keycloakUser['attributes']['role_name']) || $keycloakUser['attributes']['role_name'] !== $user['role']['name']) ||
            (empty($keycloakUser['attributes']['role_uuid']) || $keycloakUser['attributes']['role_uuid'] !== $user['role']['uuid']) ||
            (empty($keycloakUser['attributes']['org_name']) || $keycloakUser['attributes']['org_name'] !== $user['organisation']['name']) ||
            (empty($keycloakUser['attributes']['org_uuid']) || $keycloakUser['attributes']['org_uuid'] !== $user['organisation']['uuid'])
        ) {
            $change = [
                'enabled' => !$user['disabled'],
                'firstName' => $user['individual']['first_name'],
                'lastName' => $user['individual']['last_name'],
                'email' => $user['individual']['email'],
                'attributes' => [
                    'role_name' => $user['role']['name'],
                    'role_uuid' => $user['role']['uuid'],
                    'org_name' => $user['organisation']['name'],
                    'org_uuid' => $user['organisation']['uuid']
                ]
            ];
            $response = $this->restApiRequest('%s/admin/realms/%s/users/' . $keycloakUser['id'], $change, 'put');
            if (!$response->isOk()) {
                $this->_table->auditLogs()->insert([
                    'request_action' => 'keycloakUpdateUser',
                    'model' => 'User',
                    'model_id' => 0,
                    'model_title' => __('Failed to update user ({0}) in keycloak', $user['username']),
                    'changed' => [
                        'code' => $response->getStatusCode(),
                        'error_body' => $response->getStringBody()
                    ]
                ]);
            } else {
                return true;
            }
        }
        return false;
    }

    private function createUser(array $user, string $clientId)
    {
        $newUser = [
            'username' => $user['username'],
            'enabled' => !$user['disabled'],
            'firstName' => $user['individual']['first_name'],
            'lastName' => $user['individual']['last_name'],
            'email' => $user['individual']['email'],
            'attributes' => [
                'role_name' => $user['role']['name'],
                'role_uuid' => $user['role']['uuid'],
                'org_name' => $user['organisation']['name'],
                'org_uuid' => $user['organisation']['uuid']
            ]
        ];
        $response = $this->restApiRequest('%s/admin/realms/%s/users', $newUser, 'post');
        if (!$response->isOk()) {
            $this->_table->auditLogs()->insert([
                'request_action' => 'createUser',
                'model' => 'User',
                'model_id' => 0,
                'model_title' => __('Failed to create user ({0}) in keycloak {0}', $user['username']),
                'changed' => [
                    'code' => $response->getStatusCode(),
                    'error_body' => $response->getStringBody()
                ]
            ]);
        }
        $newUser = $this->restApiRequest(
            '%s/admin/realms/%s/users?username=' . $this->urlencodeEscapeForSprintf(urlencode($user['username'])),
            [],
            'get'
        );
        $users = json_decode($newUser->getStringBody(), true);
        if (empty($users[0]['id'])) {
            return false;
        }
        if (is_array($users[0]['id'])) {
            $users[0]['id'] = $users[0]['id'][0];
        }
        $user['id'] = $users[0]['id'];
        return $user['id'];
    }

    private function urlencodeEscapeForSprintf(string $input): string
    {
        return str_replace('%', '%%', $input);
    }

    public function updateMappers(): bool
    {
        $clientId = $this->getClientId();
        $response = $this->restApiRequest('%s/admin/realms/%s/clients/' . $clientId . '/protocol-mappers/models?protocolMapper=oidc-usermodel-attribute-mapper', [], 'get');
        if ($response->isOk()) {
            $mappers = json_decode($response->getStringBody(), true);
        } else {
            return false;
        }
        $enabledMappers = [];
        $defaultMappers = [
            'org_name' => 0,
            'org_uuid' => 0,
            'role_name' => 0,
            'role_uuid' => 0
        ];
        $mappersToEnable = explode(',', Configure::read('keycloak.user_meta_mapping'));
        foreach ($mappers as $mapper) {
            if ($mapper['protocolMapper'] !== 'oidc-usermodel-attribute-mapper') {
                continue;
            }
            if (in_array($mapper['name'], array_keys($defaultMappers))) {
                $defaultMappers[$mapper['name']] = 1;
                continue;
            }
            $enabledMappers[$mapper['name']] = $mapper;
        }
        $payload = [];
        foreach ($mappersToEnable as $mapperToEnable) {
            $payload[] = [
                'protocol' => 'openid-connect',
                'name' => $mapperToEnable,
                'protocolMapper' => 'oidc-usermodel-attribute-mapper',
                'config' => [
                    'id.token.claim' => true,
                    'access.token.claim' => true,
                    'userinfo.token.claim' => true,
                    'user.attribute' => $mapperToEnable,
                    'claim.name' => $mapperToEnable
                ]
            ];
        }
        foreach ($defaultMappers as $defaultMapper => $enabled) {
            if (!$enabled) {
                $payload[] = [
                    'protocol' => 'openid-connect',
                    'name' => $defaultMapper,
                    'protocolMapper' => 'oidc-usermodel-attribute-mapper',
                    'config' => [
                        'id.token.claim' => true,
                        'access.token.claim' => true,
                        'userinfo.token.claim' => true,
                        'user.attribute' => $defaultMapper,
                        'claim.name' => $defaultMapper
                    ]
                ];
            }
        }
        if (!empty($payload)) {
            $response = $this->restApiRequest('%s/admin/realms/%s/clients/' . $clientId . '/protocol-mappers/add-models', $payload, 'post');
            if (!$response->isOk()) {
                return false;
            }
        }
        return true;
    }
}
