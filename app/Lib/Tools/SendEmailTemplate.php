<?php
class SendEmailTemplate
{
    /** @var array  */
    private $viewVars = [];

    /** @var string */
    private $viewName;

    public function __construct($viewName)
    {
        $this->viewName = $viewName;
    }

    /**
     * @param string $key
     * @param mixed $value
     */
    public function set($key, $value)
    {
        $this->viewVars[$key] = $value;
    }

    /**
     * @param bool $hideDetails True when GnuPG.bodyonlyencrypted is enabled and e-mail cannot be send in encrypted form
     * @return CakeEmailBody
     * @throws CakeException
     */
    public function render($hideDetails = false)
    {
        $View = new View();
        $View->helpers = ['TextColour'];
        $View->loadHelpers();

        $View->set($this->viewVars);
        $View->set('hideDetails', $hideDetails);

        $View->viewPath = $View->layoutPath = 'Emails' . DS . 'html';
        try {
            $html = $View->render($this->viewName);
        } catch (MissingViewException $e) {
            $html = null; // HTMl template is optional
        }

        $View->viewPath = $View->layoutPath = 'Emails' . DS . 'text';
        $View->hasRendered = false;
        $text = $View->render($this->viewName);

        return new CakeEmailBody($text, $html);
    }
}
