<?php
declare(strict_types=1);

namespace App\Utility\UI;

use Cake\Validation\Validator;


class Notification
{
    public $text = '';
    public $router = null;
    public $details = null;
    public $icon = 'exclamation-circle';
    public $variant = 'primary';
    public $datetime = null;
    public $_useModal = false;
    public $_sidebarId = null;


    public function __construct(string $text, array $router, $options = [])
    {
        $this->text = $text;
        $this->router = $router;
        foreach ($options as $key => $value) {
            $this->{$key} = $value;
        }
        $this->validate();
    }

    public function get(): array
    {
        if (empty($errors)) {
            return (array) $this;
        }
        return null;
    }

    private function validate()
    {
        $validator = new Validator();

        $validator
            ->requirePresence('title', 'create')
            ->notEmptyString('title');
            
        return $validator->validate((array) $this);
    }
}
