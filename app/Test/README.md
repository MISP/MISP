# API / E2E Testing
The API test suite is powered by [Codeception](https://github.com/Codeception/Codeception) and relies on having a [docker-misp]([docker-misp](https://github.com/coolacid/docker-misp)) instance running with some extra settings.

Custom Codeception modules are used to simplify tasks as authenticating API requests, modifying the `MISP` test instance settings, validate API requests and responeses with the OpenAPI spec, mock sync requests to other `MISP` instances, and others.

## Preparation

1. Clone `docker-misp`:
    ```bash
    $ git clone https://github.com/coolacid/docker-misp.git
    ```
2. Inside your `docker-misp` clone directory, add the following `docker-compose.override.yml` file, replace `/home/myuser/MISP` with the directory of your `MISP` clone.

    ```bash
    # docker-compose.override.yml
    version: '3'
    services:
    db:
        ports:
        - "33060:3306"

    redis:
        ports:
        - "63790:6379"

    misp:
        ports:
        - "8000:80"
        - "8443:443"
        environment:
        - "HOSTNAME=https://localhost:8443"
        volumes:
        - "/home/myuser/MISP/app/Console:/var/www/MISP/app/Console"
        - "/home/myuser/MISP/app/Controller:/var/www/MISP/app/Controller"
        - "/home/myuser/MISP/app/View:/var/www/MISP/app/View"
        - "/home/myuser/MISP/app/Model:/var/www/MISP/app/Model"
        - "/home/myuser/MISP/app/webroot:/var/www/MISP/app/webroot"
        - "/home/myuser/MISP/app/Locale:/var/www/MISP/app/Locale"
        - "/home/myuser/MISP/app/Lib/Dashboard:/var/www/MISP/app/Lib/Dashboard"
        - "/home/myuser/MISP/app/Lib/EventReport:/var/www/MISP/app/Lib/EventReport"
        - "/home/myuser/MISP/app/Lib/Export:/var/www/MISP/app/Lib/Export"
        - "/home/myuser/MISP/app/Lib/Tools:/var/www/MISP/app/Lib/Tools"
        extra_hosts:
        - "host.docker.internal:host-gateway"
        
    wiremock:
        image: rodolpheche/wiremock
        command: "--verbose"
        ports:
        - "8080:8080"
    ```

3. Change directory to `docker-misp` and run:

    ```bash
    $ docker-compose up -d
    ```

4. Create a copy of `app/codeception.dist.yml` named `app/codeception.yml` and set the `docker_misp_dir` to your local `docker-misp` repo directory.


5. Install dependencies and generate `Codeception` Actor classes:
    ```bash
    $ cd app/
    $ composer install
    $ Vendor/bin/codecept build
    ```

## Running the tests
```
$ Vendor/bin/codecept run
```

## Fixtures
To easily create mock data fixtures are described in here `app/Test/_support/Helper/Fixture/Data`, these helper classes implement the `FixtureInterface` interface which defines basic methods for creating dummy arrays. The [Faker](https://github.com/fzaninotto/Faker) library is used to generate random data when possible.

Example:
```php
$fakeUser = UserFixture::fake(
    [
        'id' => (string)$userId,
        'org_id' => (string)$orgId,
        'role_id' => (string)UserFixture::ROLE_ADMIN,
    ]
);
$fakeUser->toRequest();  // returns the API request payload for this entity
$fakeUser->toResponse(); // returns the API response payload for this entity
$fakeUser->toDatabase(); // returns the database representation for this entity
```

## Modules
Custom `Codeception` modules are defined in `app/Test/_support/Helper/Module` directory to simplify tests code.

### Authentication
To perform an authenticated API request you can use the following helper:
```php
     $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);
```
This will automatically create a user with the role `admin` and add the `Authorization` header to the API request with the users auth key.

### Manipulating config settings
Some test cases require to manipulate `MISP` instances settings to test certain behavior, this can be done using the `MispSettings` module.
Add the following line in your test to set a custom config setting:
```php
$I->haveMispSetting('MISP.background_jobs', '1');
```

> **NOTE:** Setting rollback is not yet supported, so keep in mind you might have to set it back to the default value at the end of your test.

### OpenAPI validation
The `OpenApiValidator` module handles the validation of the API requests and responeses with the `MISP` OpenAPI spec located in `app/webroot/doc/openapi.yaml`.

Add the following lines to validate your requests against the OpenAPI spec:
```php
$I->validateRequest();  
$I->validateResponse();
```

### WireMock
Some features such as sync/push/pull require to interact with remote `MISP` instances to be able to test this features we can mock the expected requests, by using the `WireMock` module we can easily do that. This module relies on a docker container running [WireMock](http://wiremock.org/) and the [wiremock-php](https://github.com/rowanhill/wiremock-php) wrapper.


Example:
```php
$I->getWireMock()->stubFor(WireMock::post(WireMock::urlEqualTo('/events/index'))
    ->willReturn(WireMock::aResponse()
        ->withHeader('Content-Type', 'application/json')
        ->withBody((string)json_encode(
            [
                'event_id' => '1',
                'info' => 'foobar'
            ]
        ))));
```

When a `POST` request to `http://wiremock:8080/events/index` is triggered from the context of this test, it will return the stubbed response.

## Extras
### Debugging
It is possible to use xdebug to debug the `MISP` instance running on the docker container, it is required to add the following bash script as an entrypoint.

```bash
#!/bin/bash
apt-get update
apt-get install php-xdebug
cat > /etc/php/7.3/cli/conf.d/20-xdebug.ini <<EOL
xdebug.remote_enable = On
xdebug.remote_port = 9999
xdebug.remote_host = host.docker.internal
xdebug.idekey = VSCODE
xdebug.remote_autostart = On
xdebug.remote_connect_back = 1
EOL
/etc/init.d/php7.3-fpm restart
```

Add a volume mapping entry to `docker-compose.override.yml`:
```yaml
volumes:
    [...]
    - "./enable_xdebug.sh:/custom-entrypoint.sh"
```

More details on this [here](https://gist.github.com/righel/669644cd8e7c9db43b06e187c7d4b839).