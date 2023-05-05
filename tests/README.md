# Testing
## Runing the tests
### Start MISP in test mode
```
$ docker-compose -f docker-compose.yml -f docker-compose.dev.yml --env-file="./docker/.env.test" up --build
```

### Run tests
```
$ docker-compose -f docker-compose.yml -f docker-compose.dev.yml --env-file="./docker/.env.test" exec misp vendor/bin/phpunit
```


If running locally:

Add a `misp3_test` database to the database:
```mysql
CREATE DATABASE misp3_test;
GRANT ALL PRIVILEGES ON misp3_test.* to misp@'%';
FLUSH PRIVILEGES;
QUIT;
```

```
$ composer install
$ composer test
> sh ./tests/Helper/wiremock/start.sh
WireMock 1 started on port 8080
> phpunit
[ * ] Running DB migrations, it may take some time ...

The WireMock server is started .....
port:                         8080
enable-browser-proxying:      false
disable-banner:               true
no-request-journal:           false
verbose:                      false

PHPUnit 8.5.22 by Sebastian Bergmann and contributors.


.....                                     5 / 5 (100%)

Time: 11.61 seconds, Memory: 26.00 MB

OK (5 tests, 15 assertions)
```

Running a specific suite:
```
$ vendor/bin/phpunit --testsuite=api --testdox
```
Available suites:
* `app`: runs all test suites
* `api`: runs only api tests
* `controller`: runs only controller tests
* _to be continued ..._

By default the database is re-generated before running the test suite, to skip this step and speed up the test run set the following env variable in `phpunit.xml`:
```xml
<php>
    ...
    <env name="SKIP_DB_MIGRATIONS" value="1" />
</php>
```
## Extras
### WireMock
Some integration tests perform calls to external APIs, we use WireMock to mock the response of these API calls.

To download and run WireMock run the following script in a separate terminal:
    ```
    sh ./tests/Helper/wiremock/start.sh
    ```

You can also run WireMock with docker, check the official docs: http://wiremock.org/docs/docker/

> NOTE: When running the tests with `composer test` WireMock is automatically started and stoped after the tests finish.

The default `hostname` and `port` for WireMock are set in `phpunit.xml` as environment variables:
```xml
<php>
    ...
    <env name="WIREMOCK_HOST" value="localhost" />
    <env name="WIREMOCK_PORT" value="8080" />
</php>
```
### Coverage
HTML:
```
$ vendor/bin/phpunit --coverage-html tmp/coverage
```

XML:
```
$ vendor/bin/phpunit --verbose --coverage-clover=coverage.xml
```

### OpenAPI validation
API tests can assert the API response matches the OpenAPI specification, after the request add this line:      

```php
$this->assertResponseMatchesOpenApiSpec(self::ENDPOINT);
``` 

The default OpenAPI spec path is set in `phpunit.xml` as a environment variablea:
```xml
<php>
    ...
    <env name="OPENAPI_SPEC" value="webroot/docs/openapi.yaml" />
</php>
```

### Debugging tests
```
$ export XDEBUG_CONFIG="idekey=VSCODE"
$ phpunit
```
