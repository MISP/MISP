# Docker

## Development
Create a copy of `./docker/.env.dist`

```bash
cp ./docker/.env.dist ./docker.env.dev # <-- update your dev environment
docker-compose -f docker-compose.yml -f docker-compose.dev.yml --env-file=".env.dev" build
docker-compose -f docker-compose.yml -f docker-compose.dev.yml --env-file=".env.dev" up
```

```bash
docker-compose -f docker-compose.yml -f docker-compose.dev.yml --env-file=".env.dev" exec --user www-data php-fpm bash
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

## Testing
```bash
docker-compose -f docker-compose.yml -f docker-compose.test.yml --env-file=".env.test" build
docker-compose -f docker-compose.yml -f docker-compose.test.yml --env-file=".env.test" up -d
docker-compose --env-file=".env.test" exec --user www-data php-fpm /var/www/html/bin/cake test
```

## Production
```bash
cp ./docker/.env.dist ./docker.env # <-- update your prod environment
docker-compose --env-file="docker/.env" build
docker-compose --env-file="docker/.env" up -d
```