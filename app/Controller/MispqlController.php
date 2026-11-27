<?php
App::uses('AppController', 'Controller');
App::uses('MispTheme', 'MispTheme');
require_once APP . 'Lib/Tools/MispQL/MispQLRunner.php';
require_once APP . 'Lib/Tools/MispQL/MispQLCakeBackend.php';
require_once APP . 'Lib/Tools/MispQL/MispQLHistory.php';
require_once APP . 'Lib/Tools/MispQL/MispQLLanguagePack.php';

/**
 * MispQL statements, compiled and run by MISP: `explain` checks a script
 * without reading data, `run` runs one statement as the user, and `index`
 * is the query console.
 */
class MispqlController extends AppController
{
    const THEME = 'Overmind';

    public $uses = [];

    public $components = ['RequestHandler'];

    public function beforeFilter()
    {
        parent::beforeFilter();
        $this->_csrfTokenHeaderOnly(['explain', 'run']);
    }

    /**
     * The console exists only under Overmind, whichever theme the user has.
     */
    public function beforeRender()
    {
        parent::beforeRender();
        if (!MispTheme::carries($this->theme, 'Mispql')) {
            $this->theme = self::THEME;
            $this->viewClass = 'Theme';
        }
    }

    public function index()
    {
        $user = $this->Auth->user();
        $tables = $this->__tables();
        $pack = MispQLLanguagePack::build(
            $tables,
            $this->__backend($user, $tables),
            function ($table) use ($tables) {
                $model = $this->_restSearchModelName($tables->scope($table));
                $this->loadModel($model);
                return array_keys($this->$model->validFormats);
            },
            [MispQLCakeBackend::class, 'valueList']
        );
        $this->set('pack', $pack);
        $this->set('history', $this->__history($user));
        $this->set('title_for_layout', __('MispQL Console'));
        // The peeks are drawn by Overmind's own views; the user's theme is
        // still theirs here, before beforeRender() moves the console to Overmind.
        $reports = isset($pack['tables']->event_reports);
        $this->set('inPlace', [
            'peeks' => $this->theme === 'Overmind',
            'valueCard' => (bool)Configure::read('MISP.value_hover_card'),
            'reportReader' => $reports,
        ]);
        if ($reports) {
            $this->loadModel('EventReportTemplateVariable');
            $this->set('reportTemplateVariables', $this->EventReportTemplateVariable->getAll());
        }
    }

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
        if (($this->request->data['remember'] ?? false) === true) {
            $this->__remember($user, $statement);
        }
        if ($reply['kind'] === 'export') {
            return $this->_restSearchResponse($reply['scope'], $reply['run']);
        }
        return $this->RestResponse->viewData($reply, 'json');
    }

    private function __tables()
    {
        return new MispQLTables([MispQLCakeBackend::class, 'orderFields']);
    }

    private function __backend(array $user, MispQLTables $tables)
    {
        return new MispQLCakeBackend($user, $tables, $this->ACL, $this->_runRestSearch(...));
    }

    private function __runner(array $user)
    {
        $tables = $this->__tables();
        return new MispQLRunner($tables, $this->__backend($user, $tables));
    }

    private function __history(array $user)
    {
        $this->loadModel('UserSetting');
        return MispQLHistory::entries(
            $this->UserSetting->getValueForUser($user['id'], MispQLHistory::SETTING)
        );
    }

    /**
     * Only the console asks for this. A failure to record is logged and
     * never fails the run.
     */
    private function __remember(array $user, $statement)
    {
        try {
            $kept = MispQLHistory::add($this->__history($user), $statement, time());
            if ($kept !== null) {
                $this->UserSetting->setSettingInternal($user['id'], MispQLHistory::SETTING, $kept);
            }
        } catch (Exception $e) {
            $this->log('MispQL history not recorded: ' . $e->getMessage(), LOG_WARNING);
        }
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
