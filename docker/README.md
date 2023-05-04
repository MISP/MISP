# Docker
The Dockerfiles have a [multi-stage build](https://docs.docker.com/build/building/multi-stage/) to help serve both a `dev` and `prod` image for all of the services required for running MISP.

The `dev` image includes additional packages for debugging, test suites and volume mappings to help the developer directly modify the files in the host machine and automatically reflect this changes in the container environment.

The `prod` image has the minimum required packages to safely run MISP on a production enviroment. It fetches the code from github from a given `tag` or `branch` name instead of using a local copy of the codebase.

## Development environment
1. Create a copy of `./docker/.env.dev.dist`, update the variables values only if you need so and know what your are doing.
    ```bash
    cp ./docker/.env.dist ./docker.env.dev
    ```
2. Build the `dev` images:
    ```bash
    docker-compose -f docker-compose.yml -f docker-compose.dev.yml --env-file="./docker/.env.dev" build
    ```
3. Run the application in `dev` mode:
    ```bash
    docker-compose -f docker-compose.yml -f docker-compose.dev.yml --env-file="./docker/.env.dev" up
    ```

### Debugging
For debugging the PHP code with XDebug and VSCODE use the following configuration file:
`launch.json`:
```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Listen for Xdebug",
            "type": "php",
            "request": "launch",
            "port": 9003,
            "pathMappings": {
                "/var/www/html": "${workspaceRoot}",
            },
        },
    ]
}
```
> **NOTE**: Add `XDEBUG_SESSION_START` query parameter or `XDEBUG_SESION=VSCODE` cookie to debug your requests.

### Troubleshooting
#### Logs
You can find the MISP logs in the `./docker/logs` directory.
#### Interactive shell
If you need a shell into the MISP container, run:
```bash
docker-compose -f docker-compose.yml -f docker-compose.dev.yml --env-file="./docker/.env.dev" exec --user www-data misp bash
```
#### Permission denied
If you have permissions errors when trying to edit files from your host machine:
1. Verify your `UID` and `GID`:
```bash
$ id
uid=1000(myuser) gid=1000(myuser) groups=1000(myuser)...
```
2. Update your `.env.dev` file with the correct a `UID` and `GID`.
3. Rebuild your `misp` service:
```bash
docker-compose -f docker-compose.yml -f docker-compose.dev.yml --env-file="./docker/.env.dev" build misp
```

## Testing
```bash
docker-compose -f docker-compose.yml -f docker-compose.test.yml --env-file="./docker/.env.test" build
docker-compose -f docker-compose.yml -f docker-compose.test.yml --env-file="./docker/.env.test" up -d
docker-compose --env-file="./docker/.env.test" exec --user www-data misp /var/www/html/bin/cake test
```

## Production
1. Create a copy of `./docker/.env.dist`, update the variables values with your production values and secrets.
    ```bash
    cp ./docker/.env.dist ./docker.env
    ```
2. Build the `prod` images:
    ```bash
    docker-compose --env-file="./docker/.env" build
    ```
3. Run the application in `prod` mode:
    ```bash
    docker-compose --env-file="./docker/.env" up -d
    ```
