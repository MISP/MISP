<?php

namespace App\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Http\Server\MiddlewareInterface;
use Cake\Core\Configure;

class NamedParamsParserMiddleware implements MiddlewareInterface
{

    /**
     * This middleware allows to configure named params for specific controller/actions to keep CakePHP 2.x backwards compatibility.
     * Reads Configure::read('NamedParams') and parses the named params from the request->pass array.
     *
     * @var array
     */

    public function process(
        ServerRequestInterface $request,
        RequestHandlerInterface $handler
    ): ResponseInterface {

        $namedConfig = Configure::read('NamedParams', []);

        $action = $request->getParam('controller') . '.' . $request->getParam('action');

        if (!array_key_exists($action, $namedConfig)) {
            return $handler->handle($request);
        }

        $named = [];
        $options = ['named' => $namedConfig[$action]];
        $args = $pass = $request->getParam('pass');

        // snippet taken from cakephp 2.x CakeRoute::_parseArgs()
        foreach ($args as $param) {
            if (empty($param) && $param !== '0' && $param !== 0) {
                continue;
            }

            $separatorIsPresent = strpos($param, ':') !== false;
            if ((!isset($options['named']) || !empty($options['named'])) && $separatorIsPresent) {
                list($key, $val) = explode(':', $param, 2);
                if (in_array($key, $options['named'], true)) {
                    if (preg_match_all('/\[([A-Za-z0-9_-]+)?\]/', $key, $matches, PREG_SET_ORDER)) {
                        $matches = array_reverse($matches);
                        $parts = explode('[', $key);
                        $key = array_shift($parts);
                        $arr = $val;
                        foreach ($matches as $match) {
                            if (empty($match[1])) {
                                $arr = array($arr);
                            } else {
                                $arr = array(
                                    $match[1] => $arr
                                );
                            }
                        }
                        $val = $arr;
                    }
                    $named = array_merge_recursive($named, array($key => $val));

                    // remove the named param from the pass array
                    $pass = array_values(array_diff($pass, array($param)));
                }
            }
        }

        $queryParams = array_merge($request->getQueryParams(), $named);

        $request = $request->withParam('pass', $pass);
        $request = $request->withParam('named', $named);
        $request = $request->withQueryParams($queryParams);

        return $handler->handle($request);
    }
}
