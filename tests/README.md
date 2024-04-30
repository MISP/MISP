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

Update the `app_local.php` file found in /path/to/MISP/config/app_local.php

```
return [
    ...
    'Datasources' => [
        ...
        'test' => [
            'username' => 'misp',
            'password' => 'YOUR_MYSQL_MISP_USER_PASSWORD',
            'database' => 'misp3_test'
        ]
```

```
$ composer install
$ composer test
> phpunit
[ * ] Running DB migrations, it may take some time ...

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

The default OpenAPI spec path is set in `phpunit.xml` as a environment variable:
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
