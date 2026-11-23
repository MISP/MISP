<?php
App::uses('AppController', 'Controller');
require_once APP . 'Lib/Tools/MispQL/MispQLRunner.php';
require_once APP . 'Lib/Tools/MispQL/MispQLCakeBackend.php';

/**
 * MispQL statements, compiled and run by MISP: `explain` checks a script
 * without reading data, `run` runs one statement as the user.
 */
class MispqlController extends AppController
{
    public $uses = [];

    public $components = ['RequestHandler'];

    public function explain()
    {
        $this->request->allowMethod(['post']);
        $script = $this->__text('script');
        $user = $this->_closeSession();
        try {
            $reply = $this->__runner($user)->explain($script);
        } catch (MispQLErrors $e) {
            return $this->__refuse($e);
        }
        return $this->RestResponse->viewData($reply, 'json');
    }

    public function run()
    {
        $this->request->allowMethod(['post']);
        $statement = $this->__text('statement');
        $user = $this->_closeSession();
        try {
            $reply = $this->__runner($user)->run($statement);
        } catch (MispQLErrors $e) {
            return $this->__refuse($e);
        }
        if ($reply['kind'] === 'export') {
            return $this->_restSearchResponse($reply['scope'], $reply['run']);
        }
        return $this->RestResponse->viewData($reply, 'json');
    }

    private function __runner(array $user)
    {
        $tables = new MispQLTables([MispQLCakeBackend::class, 'orderFields']);
        $backend = new MispQLCakeBackend($user, $tables, $this->ACL, $this->_runRestSearch(...));
        return new MispQLRunner($tables, $backend);
    }

    private function __text($key)
    {
        $data = $this->request->data;
        if (!is_array($data) || !isset($data[$key]) || !is_string($data[$key])) {
            throw new BadRequestException(__('Send the %s as a string in a JSON body.', $key));
        }
        return $data[$key];
    }

    private function __refuse(MispQLErrors $e)
    {
        $count = count($e->errors);
        return $this->RestResponse->throwException(
            400,
            __('Invalid query'),
            $this->request->here,
            false,
            false,
            [],
            [
                'message' => __n('%s error', '%s errors', $count, $count),
                'language' => MispQLCompiler::LANGUAGE,
                'errors' => $e->errors,
            ]
        );
    }
}
