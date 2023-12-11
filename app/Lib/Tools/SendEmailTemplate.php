<?php
class SendEmailTemplate
{
    /** @var array  */
    private $viewVars = [];

    /** @var string */
    private $viewName;

    /** @var string|null */
    private $referenceId;

    /** @var string */
    private $listUnsubscribe;

    /** @var string|null */
    private $subject;

    public function __construct($viewName)
    {
        $this->viewName = $viewName;
    }

    /**
     * This value will be used for grouping emails in mail client.
     * @param string|null $referenceId
     * @return string|void
     */
    public function referenceId($referenceId = null)
    {
        if ($referenceId === null) {
            return $this->referenceId;
        }
        $this->referenceId = $referenceId;
    }

    /**
     * @param string|null $listUnsubscribe
     * @return string|void
     */
    public function listUnsubscribe($listUnsubscribe = null)
    {
        if ($listUnsubscribe === null) {
            return $this->listUnsubscribe;
        }
        $this->listUnsubscribe = $listUnsubscribe;
    }

    /**
     * Get subject from template. Must be called after render method.
     * @param string|null $subject
     * @return string|void
     */
    public function subject($subject = null)
    {
        if ($subject === null) {
            return $this->subject;
        }
        $this->subject = $subject;
    }

    /**
     * Set template variable.
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
        $View->autoLayout = false;
        $View->helpers = ['TextColour'];
        $View->loadHelpers();

        $View->set($this->viewVars);
        $View->set('hideDetails', $hideDetails);

        try {
            $View->viewPath = $View->layoutPath = 'Emails' . DS . 'html' . DS . 'Custom';
            $html = $View->render($this->viewName); // Attempt to load a custom template if it exists
        } catch (MissingViewException $e) {
            $View->viewPath = $View->layoutPath = 'Emails' . DS . 'html';
            try {
                $html = $View->render($this->viewName);
            } catch (MissingViewException $e) {
                $html = null; // HTML template is optional
            }
        }


        $View->hasRendered = false;
        try {
            $View->viewPath = $View->layoutPath = 'Emails' . DS . 'text' . DS . 'Custom';
            $text = $View->render($this->viewName); // Attempt to load a custom template if it exists
        } catch (MissingViewException $e) {
            $View->viewPath = $View->layoutPath = 'Emails' . DS . 'text';
            $text = $View->render($this->viewName);
        }

        // Template can change default subject.
        if ($View->get('subject')) {
            $this->subject = $View->get('subject');
        }

        return new CakeEmailBody($text, $html);
    }
}
