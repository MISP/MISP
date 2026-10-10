<?php
App::uses('AppController', 'Controller');
App::uses('ValueConditionRewriter', 'Tools');

/**
 * Stored attribute values, each with the attributes holding it that the user
 * can see. A value no visible attribute holds is reported as missing.
 *
 * @property AttributeValue $AttributeValue
 * @property MispAttribute $MispAttribute
 */
class ValuesController extends AppController
{
    const LIMIT = 60;

    const MAX_LIMIT = 1000;

    const MAX_PAGE = 1000000;

    const SEARCH_MODES = ['search', 'like', 'exact'];

    public $components = ['RequestHandler'];

    public $uses = ['AttributeValue'];

    /**
     * GET /values/view/<id>, /values/view/sha256:<hex> or /values/view?value=…,
     * or POST {"value": …}. page and limit page the attributes.
     *
     * @param string|null $id
     * @return CakeResponse|void
     */
    public function view($id = null)
    {
        $params = $this->__params();
        if ($id !== null) {
            $address = ['id' => $id];
        } elseif (isset($this->request->params['named']['sha256'])) {
            $address = ['sha256' => $this->request->params['named']['sha256']];
        } elseif (isset($params['value'])) {
            $address = ['value' => $params['value']];
        } else {
            throw new BadRequestException(__('Name the value by its id, its sha256 or its text.'));
        }
        list($page, $limit) = $this->__paging($params);
        $value = $this->AttributeValue->findAddressed($address);
        $count = 0;
        $attributes = [];
        if ($value !== null) {
            $this->loadModel('MispAttribute');
            $attributes = $this->MispAttribute->fetchAttributes($this->Auth->user(), [
                'conditions' => ['OR' => [
                    'Attribute.value1_id' => $value['id'],
                    'Attribute.value2_id' => $value['id'],
                ]],
                'flatten' => 1,
                'fields' => ['Event.published', 'Event.sharing_group_id', 'Object.name', 'Object.uuid'],
                'order' => 'Attribute.id DESC',
                'page' => $page,
                'limit' => $limit,
            ], $count, true);
        }
        if ($count === 0) {
            throw new NotFoundException(__('Invalid value.'));
        }
        $summary = [
            'id' => $value['id'],
            'value' => $value['value'],
            'sha256' => hash('sha256', $value['value']),
            'attribute_count' => $count,
        ];
        if ($this->_isRest()) {
            $out = [];
            foreach ($attributes as $row) {
                $out[] = $this->__attribute($row);
            }
            return $this->RestResponse->viewData(['Value' => $summary, 'Attribute' => $out], $this->response->type());
        }
        if (!isset($address['id'])) {
            return $this->redirect(['action' => 'view', $value['id']]);
        }
        $this->request->params['paging']['Attribute'] = [
            'page' => $page,
            'current' => count($attributes),
            'count' => $count,
            'prevPage' => $page > 1,
            'nextPage' => $page * $limit < $count,
            'pageCount' => (int)ceil($count / $limit),
            'order' => null,
            'limit' => $limit,
            'options' => $limit === self::LIMIT ? [] : ['limit' => $limit],
            'paramType' => 'named',
        ];
        $this->set('value', $summary);
        $this->set('attributes', $attributes);
        $this->set('title_for_layout', __('Value'));
    }

    /**
     * POST {"value": …, "mode": "search"|"like"|"exact", "page": …, "limit": …}.
     * search finds the text from the start of a word, like takes a LIKE
     * pattern and exact matches the whole value, ignoring case.
     *
     * @return CakeResponse
     */
    public function search()
    {
        $params = $this->__params();
        $text = $params['value'] ?? null;
        if (!is_scalar($text) || (string)$text === '' || strlen((string)$text) > AttributeValue::MAX_BYTES) {
            throw new BadRequestException(__('Give the text to search for as value.'));
        }
        $text = (string)$text;
        $mode = $params['mode'] ?? 'search';
        if (!in_array($mode, self::SEARCH_MODES, true)) {
            throw new BadRequestException(__('Invalid mode: use search, like or exact.'));
        }
        list($page, $limit) = $this->__paging($params);
        if ($mode === 'exact') {
            $ids = $this->AttributeValue->resolveCi([$text])[$text];
        } else {
            $found = $mode === 'like'
                ? $this->AttributeValue->resolveLike($text, ValueConditionRewriter::OVERFLOW)
                : $this->AttributeValue->resolveSearch($text, ValueConditionRewriter::OVERFLOW);
            if ($found['overflow']) {
                throw new BadRequestException(__('The search matches too many values, narrow it down.'));
            }
            $ids = $found['ids'];
        }
        $this->loadModel('MispAttribute');
        $visible = $this->MispAttribute->visibleValueIds($this->Auth->user(), $ids, $page * $limit);
        $ids = array_slice($visible, ($page - 1) * $limit, $limit);
        $values = $this->AttributeValue->fetchValues($ids);
        $out = [];
        foreach ($ids as $id) {
            if (isset($values[$id])) {
                $out[] = ['Value' => ['id' => $id, 'value' => $values[$id]]];
            }
        }
        return $this->RestResponse->viewData($out, 'json');
    }

    /**
     * @return array The query string, with the posted fields over it.
     */
    private function __params()
    {
        $params = $this->request->query;
        if ($this->request->is('post') && is_array($this->request->data)) {
            $params = array_merge($params, $this->request->data);
        }
        return $params;
    }

    /**
     * @param array $params
     * @return int[] [page, limit]
     */
    private function __paging(array $params)
    {
        $named = $this->request->params['named'] ?? [];
        $page = filter_var($params['page'] ?? $named['page'] ?? 1, FILTER_VALIDATE_INT, [
            'options' => ['min_range' => 1, 'max_range' => self::MAX_PAGE],
        ]);
        $limit = filter_var($params['limit'] ?? $named['limit'] ?? self::LIMIT, FILTER_VALIDATE_INT, [
            'options' => ['min_range' => 1, 'max_range' => self::MAX_LIMIT],
        ]);
        if ($page === false || $limit === false) {
            throw new BadRequestException(__('Invalid paging: page from 1 to %s, limit from 1 to %s.', self::MAX_PAGE, self::MAX_LIMIT));
        }
        return [$page, $limit];
    }

    /**
     * @param array $row As fetchAttributes() returns it.
     * @return array
     */
    private function __attribute(array $row)
    {
        $attribute = $row['Attribute'];
        unset($attribute['value1'], $attribute['value2']);
        $event = $row['Event'];
        $attribute['Event'] = [
            'id' => $event['id'],
            'uuid' => $event['uuid'],
            'info' => $event['info'],
            'date' => $event['date'],
            'distribution' => $event['distribution'],
            'sharing_group_id' => $event['sharing_group_id'],
            'published' => $event['published'],
            'timestamp' => $event['timestamp'],
            'Orgc' => $event['Orgc'],
        ];
        if (!empty($attribute['object_id'])) {
            $attribute['Object'] = [
                'id' => $row['Object']['id'],
                'uuid' => $row['Object']['uuid'],
                'name' => $row['Object']['name'],
                'distribution' => $row['Object']['distribution'],
                'sharing_group_id' => $row['Object']['sharing_group_id'],
            ];
        }
        $attribute['Tag'] = [];
        foreach ($row['AttributeTag'] ?? [] as $attributeTag) {
            if (isset($attributeTag['Tag'])) {
                $attribute['Tag'][] = $attributeTag['Tag'];
            }
        }
        return $attribute;
    }
}
