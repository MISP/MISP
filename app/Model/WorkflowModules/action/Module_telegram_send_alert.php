<?php
include_once APP . 'Model/WorkflowModules/action/Module_webhook.php';

class Module_telegram_send_alert extends Module_webhook
{
    public $id = 'telegram-send-alert';
    public $name = 'Telegram Send Alert';
    public $version = '0.1';
    public $description = 'Send a message alert to a Telegram channel';
    public $icon_path = 'Telegram.png';

    private $telegram_url = "https://api.telegram.org/";

    public function __construct()
    {
        parent::__construct();
        $this->params = [
            [
                'id' => 'bot_token',
                'label' => 'Telegram Bot Token',
                'type' => 'input',
                'placeholder' => 'bot123:ABC',
            ],
            [
                'id' => 'chat_id',
                'label' => 'Telegram Chat id',
                'type' => 'input',
                'placeholder' => '123',
            ],
            [
                'id' => 'message_body_template',
                'label' => 'Message Body Template',
                'type' => 'textarea',
                'placeholder' => __('Template redendered using Jinja2'),
                'jinja_supported' => true,
            ],
        ];
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors = []): bool
    {
        $rData = $roamingData->getData();
        $params = $this->getParamsWithValues($node, $rData);

	$bot_token = $params['bot_token']['value'];
	$chat_id = $params['chat_id']['value'];
	$message_body = $params['message_body_template']['value'];

	$data = [
		'chat_id' =>  $chat_id,
		'text' => $message_body,
		'parse_mode' => "HTML",
	];

	$url = $this->telegram_url . "bot" . $bot_token . "/sendMessage";

	$response = $this->doRequest(
		$url,
		'application/json',
		$data
	);

	if (!$response->isOk()) {
		if ($response->code === 401) {
			$errors[] = __('Authentication failed');
			return false;
		}
		$errors[] = __('Something went wrong with the request: %s', $response->body);
		return false;
	}
	
	return true;
    }
    
}
