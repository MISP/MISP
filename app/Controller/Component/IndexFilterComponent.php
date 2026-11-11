<?php

/**
 * Get filter parameters from index searches
 */

class IndexFilterComponent extends Component
{
    /** @var Controller */
    public $Controller;

    /** @var bool|null  */
    private $isRest = null;

    // A shorter quick filter term matches nearly every row of a log table, so
    // it costs a full scan for nothing.
    const QUICK_FILTER_MIN_LENGTH = 2;

    // Cap on the user / organisation ids a quick filter term resolves to.
    const QUICK_FILTER_MAX_RESOLVED_IDS = 50;

    // Used for isApiFunction(), a check that returns true if the controller & action combo matches an action that is a non-xml and non-json automation method
    // This is used to allow authentication via headers for methods not covered by _isRest() - as that only checks for JSON and XML formats
    const AUTOMATION_ARRAY = array(
        'events' => array('csv', 'nids', 'hids', 'xml', 'restSearch', 'stix', 'updateGraph', 'downloadOpenIOCEvent'),
        'attributes' => array('text', 'downloadAttachment', 'returnAttributes', 'restSearch', 'rpz', 'bro'),
        'objects' => array('restSearch'),
    );

    public function initialize(Controller $controller)
    {
        $this->Controller = $controller;
    }

    // generic function to standardise on the collection of parameters. Accepts posted request objects, url params, named url params
    public function harvestParameters($paramArray, &$exception = [], array $options = [])
    {
        $request = $this->Controller->request;
        $data = [];
        if ($request->is('post')) {
            if (empty($request->data)) {
                $exception = $this->Controller->RestResponse->throwException(
                    400,
                    __('Either specify the search terms in the url, or POST a json with the filter parameters.'),
                    '/' . $request->params['controller'] . '/' . $this->Controller->action
                );
                return false;
            } else {
                if (isset($request->data['request'])) {
                    $data = $request->data['request'];
                } else {
                    $data = $request->data;
                }
            }
        }

        $data = $this->__massageData($data, $request, $paramArray, !empty($options['fromQuery']));

        $this->Controller->set('passedArgs', json_encode($this->Controller->passedArgs));
        return $data;
    }

    private function __massageData($data, $request, $paramArray, $fromQuery = false)
    {
        $data = array_filter($data, function($paramName) use ($paramArray) {
            return in_array($paramName, $paramArray, true);
        }, ARRAY_FILTER_USE_KEY);

        if (!empty($paramArray)) {
            foreach ($paramArray as $p) {
                if (isset($request->params['named'][$p])) {
                    $data[$p] = str_replace(';', ':', $request->params['named'][$p]);
                }
            }
            /*
             * Opt-in, because it widens what an index accepts: a named URL
             * segment cannot carry a '/', so a filter on a URL or a path has
             * to travel in the query string. Only the caller's own paramArray
             * is read back, so no unexpected key can reach the conditions.
             */
            if ($fromQuery) {
                foreach ($paramArray as $p) {
                    if (isset($request->query[$p]) && $request->query[$p] !== '') {
                        $data[$p] = $request->query[$p];
                    }
                }
            }
        }
        foreach ($data as &$v) {
            if (is_string($v)) {
                $v = trim($v);
                if (strpos($v, '||')) {
                    $v = explode('||', $v);
                }
            }
        }
        unset($v);
        return $data;

    }

    public function isRest()
    {
        // This method is surprisingly slow and called many times for one request, so it make sense to cache the result.
        if ($this->isRest !== null) {
            return $this->isRest;
        }
        $api = $this->isApiFunction($this->Controller->request->params['controller'], $this->Controller->request->params['action']);
        if (isset($this->Controller->RequestHandler) && ($api || $this->isJson() || $this->Controller->RequestHandler->isXml() || $this->isCsv())) {
            $this->isRest = true;
            return true;
        } else {
            $this->isRest = false;
            return false;
        }
    }

    public function isXhr()
    {
        return $this->Controller->request->header('X-Requested-With') === 'XMLHttpRequest';
    }

    public function isJson()
    {
        return $this->Controller->request->header('Accept') === 'application/json' || $this->Controller->RequestHandler->prefers() === 'json';
    }

    public function isCsv()
    {
        return $this->Controller->request->header('Accept') === 'text/csv' || $this->Controller->RequestHandler->prefers() === 'csv';
    }

    /**
     * @param string $controller
     * @param string $action
     * @return bool
     */
    public function isApiFunction($controller, $action)
    {
        return isset(self::AUTOMATION_ARRAY[$controller]) && in_array($action, self::AUTOMATION_ARRAY[$controller], true);
    }

    /**
     * The quick filter term is carried in the query string rather than as a
     * named parameter: a named URL segment cannot hold a '/', and searching
     * the access log means searching URLs. Named parameters are still read so
     * that an older bookmark, or an API caller, keeps working.
     *
     * @param string $name
     * @return string empty string when nothing was searched for
     */
    public function quickFilterTerm($name = 'quickFilter')
    {
        $request = $this->Controller->request;
        $term = $request->query($name);
        if ($term === null && isset($request->params['named'][$name])) {
            $term = $request->params['named'][$name];
        }
        if (is_array($term)) {
            // harvestParameters() splits a value on '||' — put it back together.
            $term = implode('||', $term);
        }
        return is_string($term) ? trim($term) : '';
    }

    /**
     * Build the OR condition behind a free-text quick filter box.
     *
     * The log indexes (application / audit / access) share one search box but
     * not one schema, so each caller declares which columns the term should
     * reach. Only columns of $model end up in the returned condition — user
     * and organisation are resolved to a list of ids first — so the result
     * stays usable in a find('count') with no containment, and next to an ACL
     * condition.
     *
     * $spec keys, all optional:
     *  - like     : string[] columns matched with LIKE %term%
     *  - numeric  : string[] columns matched exactly, only for an all-digit term
     *  - ip       : column holding a packed address (inet_pton), exact match
     *  - ip_like  : column holding a plain-string address, matched with LIKE
     *  - user     : foreign key resolved through User.email
     *  - org      : foreign key resolved through Organisation.name / .uuid
     *
     * @param string $term
     * @param string $model model alias the columns belong to
     * @param array $spec
     * @return array condition array, empty when the term is too short to run
     */
    public function quickFilterConditions($term, $model, array $spec)
    {
        $term = trim((string)$term);
        if (mb_strlen($term) < self::QUICK_FILTER_MIN_LENGTH) {
            return [];
        }
        // A '%' or a '_' typed by hand is a literal, not a wildcard.
        $like = '%' . addcslashes($term, '%_\\') . '%';
        $lowerLike = mb_strtolower($like);
        $or = [];

        foreach ($spec['like'] ?? [] as $field) {
            $or["LOWER($model.$field) LIKE"] = $lowerLike;
        }
        if (ctype_digit($term)) {
            foreach ($spec['numeric'] ?? [] as $field) {
                $or["$model.$field"] = (int)$term;
            }
        }
        if (!empty($spec['ip_like'])) {
            $or["$model.{$spec['ip_like']} LIKE"] = $like;
        }
        if (!empty($spec['ip']) && filter_var($term, FILTER_VALIDATE_IP)) {
            $or["$model.{$spec['ip']}"] = inet_pton($term);
        }
        if (!empty($spec['user'])) {
            $ids = $this->__resolveIds($model, 'User', ['LOWER(User.email) LIKE' => $lowerLike]);
            if (!empty($ids)) {
                $or["$model.{$spec['user']}"] = $ids;
            }
        }
        if (!empty($spec['org'])) {
            $ids = $this->__resolveIds($model, 'Organisation', ['OR' => [
                'LOWER(Organisation.name) LIKE' => $lowerLike,
                'LOWER(Organisation.uuid) LIKE' => $lowerLike,
            ]]);
            if (!empty($ids)) {
                $or["$model.{$spec['org']}"] = $ids;
            }
        }
        if (empty($or)) {
            // Every branch was ruled out — a word typed into an index whose
            // only searchable column is numeric, say. Match nothing rather
            // than drop the condition, which would show the whole table back.
            return ["$model.id" => -1];
        }
        return ['OR' => $or];
    }

    /**
     * Ids of the rows of an associated model the term points at. Capped: past
     * a few dozen matches the term is too vague for the id list to say
     * anything, and a long IN () is not worth building.
     *
     * @param string $model
     * @param string $association
     * @param array $conditions
     * @return array
     */
    private function __resolveIds($model, $association, array $conditions)
    {
        return $this->Controller->{$model}->{$association}->find('column', [
            'fields' => ["$association.id"],
            'conditions' => $conditions,
            'limit' => self::QUICK_FILTER_MAX_RESOLVED_IDS,
            'recursive' => -1,
        ]);
    }
}
