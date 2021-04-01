<?php

App::uses('ComponentCollection', 'Controller');
App::uses('RestResponseComponent', 'Controller/Component');
App::uses('File', 'Utility');

class APIShell extends AppShell {

    private $filename = 'API_Doc.md';
    private $notice = '';

    public function startup() {
        $collection = new ComponentCollection();
        $this->RestResponseComponent = $collection->load('RestResponse');
        $this->notice = __('The following API documentation is derived directly from [MISP RestResponseComponent\'s source code](app/Controller/Component/RestResponseComponent.php)');
    }

    public function genDoc()
    {
        $basicUser = [
            'id' => 0,
            'email' => 'SYSTEM',
            'Organisation' => ['name' => 'SYSTEM'],
            'Role' => [
                'perm_site_admin' => true,
            ]
        ];
        $api = $this->RestResponseComponent->getScopedApiInfo($basicUser);
        $apiFieldsContraint = $this->RestResponseComponent->getAllApisFieldsConstraint($basicUser);

        $doc = $this->genNoticeDoc();
        foreach ($api as $model => $apiEntries) {
            $doc .= $this->genMDTitle(Inflector::humanize($model), 1);
            foreach ($apiEntries as $apiEntry) {
                $baseURL = $apiEntry['url'];
                $offset = strpos($baseURL, '/[');
                if ($offset !== false) {
                    $baseURL = substr($baseURL, 0, $offset);
                }
                $fieldsConstraints = $apiFieldsContraint[$baseURL];
                $doc .= $this->genEndpointDoc($apiEntry, $fieldsConstraints);
            }
        }
        $saved = $this->saveDoc($doc);
        if ($saved) {
            echo __('Successfully saved API documentation') . PHP_EOL;
        } else {
            echo __('Could not save API documentation') . PHP_EOL;
        }
    }

    private function genEndpointDoc($apiEntry, $fieldsConstraints=[])
    {
        $doc = $this->genMDTitle(Inflector::humanize($apiEntry['action']), 2);
        $doc .= $apiEntry['description'] . PHP_EOL;
        $doc .= $this->genMDCode($apiEntry['url']);
        $doc .= $this->genMDBR();

        $doc .= $this->genMDTitle(__('URL Parameters'), 3);
        $doc .= $this->genParamsDoc($apiEntry, 'params', $fieldsConstraints);
        $doc .= $this->genMDBR();

        $doc .= $this->genMDTitle(__('Parameters'), 3);
        if (!empty($apiEntry['mandatory'])) {
            $doc .= $this->genMDTitle(__('Mandatory'), 4);
            $doc .= $this->genParamsDoc($apiEntry, 'mandatory', $fieldsConstraints);
            $doc .= $this->genMDBR();
        }
        if (!empty($apiEntry['optional'])) {
            $doc .= $this->genMDTitle(__('Optional'), 4);
            $doc .= $this->genParamsDoc($apiEntry, 'optional', $fieldsConstraints);
        }
        $doc .= $this->genMDBR();
        return $doc;
    }

    private function genNoticeDoc()
    {
        $doc = $this->genMDTitle(__('API Documentation'), 1);
        $doc .= $this->notice . PHP_EOL;
        return $doc;
    }

    private function genParamsDoc($apiEntry, $paramName, $fieldsConstraints)
    {
        $doc = '';
        if (!empty($apiEntry[$paramName])) {
            $header = [__('Name'), __('Type'), __('Description')];
            $rows = [];
            foreach ($apiEntry[$paramName] as $param) {
                if (is_array($param)) {
                    $type = 'Object';
                    $description = json_encode($param);
                } else {
                    if (isset($fieldsConstraints[$param]) && !is_null($fieldsConstraints[$param])) {
                        $type = $fieldsConstraints[$param]['type'];
                        $description = !empty($fieldsConstraints[$param]['help']) ? $fieldsConstraints[$param]['help'] : '';
                    } else {
                        $type = '';
                        $description = '';
                    }
                }
                $rows[] = [
                    $param,
                    $type,
                    $description
                ];
            }
            $doc = $this->genMDTable($header, $rows);
        }
        return $doc;
    }

    private function saveDoc($MDDoc)
    {
        $file = new File(ROOT . DS . 'docs' . DS . $this->filename, true);
        $saved = $file->write($MDDoc);
        $file->close();
        return $saved;
    }

    private function genMDBR($count=1)
    {
        return str_repeat(PHP_EOL, $count);
    }

    private function genMDTitle($text, $level=1)
    {
        return sprintf('%s %s', str_repeat('#', $level), $text . PHP_EOL);
    }

    private function genMDTable($header, $rows)
    {
        $doc = $this->genMDTableRow($header);
        $doc .= $this->genMDTableRow(array_map(function () {
            return '--';
        }, $header));
        foreach ($rows as $row) {
            $doc .= $this->genMDTableRow($row);
        }
        return $doc;
    }

    private function genMDTableRow($row)
    {
        $doc = '| ';
        foreach ($row as $entry) {
            $entryText = is_array($entry) ? json_encode($entry) : $entry;
            $doc .= $entryText . ' |';
        }
        $doc .= PHP_EOL;
        return $doc;
    }

    private function genLink($text, $url)
    {
        return sprintf('[%s](%s)', $text, $url);
    }

    private function genMDCode($code)
    {
        return '```' . PHP_EOL . $code . PHP_EOL . '```';
    }
}
