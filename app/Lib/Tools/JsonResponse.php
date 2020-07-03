<?php
class JsonResponse extends CakeResponse
{
    public function __construct($body)
    {
        $json = json_encode($body);
        if ($json === false) {
            throw new Exception('Could not convert body to JSON.');
        }
        parent::__construct(array('body' => $json, 'type' => 'json'));
    }
}
