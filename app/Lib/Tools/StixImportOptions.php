<?php
require_once __DIR__ . '/JsonTool.php';

/**
 * Resolves the STIX document and the import options of a STIX upload, for the
 * REST API and the web form alike.
 */
class StixImportOptions
{
    const DISTRIBUTION_LEVELS = [0, 1, 2, 3, 4];
    const SHARING_GROUP = 4;

    // Legacy flags read from the URL path after the STIX version
    const POSITIONAL = [
        'publish', 'force_contextual_data', 'galaxies_as_tags', 'debug'
    ];

    /** @var bool */
    private $isSiteAdmin;

    /** @var int[] */
    private $sharingGroupIds;

    /** @var int */
    private $defaultDistribution;

    /**
     * @param bool $isSiteAdmin
     * @param int[] $sharingGroupIds Sharing groups the user is authorised for
     * @param int $defaultDistribution Instance default event distribution
     */
    public function __construct(
        $isSiteAdmin,
        array $sharingGroupIds,
        $defaultDistribution
    ) {
        $this->isSiteAdmin = (bool)$isSiteAdmin;
        $this->sharingGroupIds = array_map('intval', $sharingGroupIds);
        $this->defaultDistribution = (int)$defaultDistribution;
    }

    /**
     * The body is either a JSON envelope (`stix` beside the options, optionally
     * wrapped in `request`) or the raw STIX document. The URL wins over the
     * body: path flags, then named params, then the query string.
     *
     * @param mixed $data Decoded request body
     * @param string $rawBody
     * @param array $positional URL path segments after the STIX version
     * @param array $named URL named params
     * @param array $query Query string params
     * @return array [STIX document, import options]
     * @throws InvalidArgumentException
     */
    public function fromRest(
        $data,
        $rawBody,
        array $positional,
        array $named,
        array $query
    ) {
        // A multipart upload has no raw body: nothing to read the document from
        if (!is_string($rawBody) || trim($rawBody) === '') {
            throw self::emptyDocument();
        }
        if (isset($data['request']) && is_array($data['request'])) {
            $data = $data['request'];
        }
        $body = [];
        if (is_array($data) && array_key_exists('stix', $data)) {
            $document = $data['stix'];
            unset($data['stix']);
            $body = $data;
            if (is_array($document) && !empty($document)) {
                $document = JsonTool::encode($document);
            }
        } else {
            $document = $rawBody;
        }
        if (!is_string($document) || trim($document) === '') {
            throw self::emptyDocument();
        }

        $fromPath = [];
        foreach (array_values($positional) as $index => $value) {
            if (isset(self::POSITIONAL[$index])) {
                $fromPath[self::POSITIONAL[$index]] = $value;
            }
        }
        $params = array_merge(
            self::debugAlias($body),
            $fromPath,
            self::debugAlias($named),
            self::debugAlias($query)
        );
        return [$document, $this->resolve($params)];
    }

    /**
     * Empty form fields, such as a blank select, fall back to the default.
     * The form names the galaxy option `galaxies_handling`.
     *
     * @param array $form Fields of the web upload form
     * @return array Import options
     * @throws InvalidArgumentException
     */
    public function fromForm(array $form)
    {
        $form = array_filter($form, function ($value) {
            return $value !== '';
        });
        if (isset($form['galaxies_handling'])) {
            $form['galaxies_as_tags'] = $form['galaxies_handling'];
        }
        return $this->resolve($form);
    }

    /**
     * @param array $params
     * @return array
     * @throws InvalidArgumentException
     */
    private function resolve(array $params)
    {
        $options = [
            'publish' => self::readBoolean($params, 'publish', false),
        ];
        [$options['distribution'], $options['sharing_group_id']] =
            $this->readDistribution($params, false);
        $options['original_file'] =
            self::readBoolean($params, 'original_file', true);
        $options['force_contextual_data'] =
            self::readBoolean($params, 'force_contextual_data', true);
        $options['galaxies_as_tags'] =
            self::readBoolean($params, 'galaxies_as_tags', false);
        [$options['cluster_distribution'], $options['cluster_sharing_group_id']] =
            $this->readDistribution($params, true);
        $options['debug'] = $this->isSiteAdmin ?
            self::readBoolean($params, 'debug', false) :
            false;
        return $options;
    }

    /**
     * @param array $params
     * @param bool $cluster
     * @return array [distribution, sharing group id or null]
     * @throws InvalidArgumentException
     */
    private function readDistribution(array $params, $cluster)
    {
        $prefix = $cluster ? 'cluster_' : '';
        $distribution = self::readInteger($params, $prefix . 'distribution');
        $sharingGroupId = self::readInteger(
            $params,
            $prefix . 'sharing_group_id'
        );
        if ($distribution === null) {
            $distribution = $this->defaultDistribution;
        }
        if (!in_array($distribution, self::DISTRIBUTION_LEVELS, true)) {
            throw new InvalidArgumentException($cluster ?
                __('Wrong cluster distribution level') :
                __('Wrong distribution level'));
        }
        if ($distribution !== self::SHARING_GROUP) {
            return [$distribution, null];
        }
        if ($sharingGroupId === null) {
            throw new InvalidArgumentException($cluster ?
                __('The cluster sharing group id is needed when the cluster distribution is set to 4 ("Sharing group").') :
                __('The sharing group id is needed when the distribution is set to 4 ("Sharing group").'));
        }
        if (!in_array($sharingGroupId, $this->sharingGroupIds, true)) {
            throw new InvalidArgumentException($cluster ?
                __('Please select a valid cluster sharing group id.') :
                __('Please select a valid sharing group id.'));
        }
        return [$distribution, $sharingGroupId];
    }

    /**
     * @return InvalidArgumentException
     */
    private static function emptyDocument()
    {
        return new InvalidArgumentException(
            __('The STIX document is empty or missing.')
        );
    }

    /**
     * @param array $params
     * @return array
     */
    private static function debugAlias(array $params)
    {
        if (!isset($params['debug']) && isset($params['debugging'])) {
            $params['debug'] = $params['debugging'];
        }
        return $params;
    }

    /**
     * @param array $params
     * @param string $key
     * @param bool $default
     * @return bool
     * @throws InvalidArgumentException
     */
    private static function readBoolean(array $params, $key, $default)
    {
        if (!isset($params[$key])) {
            return $default;
        }
        $value = $params[$key];
        if (is_bool($value)) {
            return $value;
        }
        if ($value === 1 || $value === 0) {
            return $value === 1;
        }
        if (is_string($value)) {
            $value = strtolower($value);
            if ($value === '1' || $value === 'true') {
                return true;
            }
            if ($value === '0' || $value === 'false') {
                return false;
            }
        }
        throw new InvalidArgumentException(__(
            'Invalid value for %s: expected 1, 0, true or false.',
            $key
        ));
    }

    /**
     * @param array $params
     * @param string $key
     * @return int|null
     * @throws InvalidArgumentException
     */
    private static function readInteger(array $params, $key)
    {
        if (!isset($params[$key])) {
            return null;
        }
        $value = $params[$key];
        if (is_int($value)) {
            return $value;
        }
        if (is_string($value) && preg_match('/\A\d+\z/', $value)) {
            return (int)$value;
        }
        throw new InvalidArgumentException(__(
            'Invalid value for %s: expected an integer.',
            $key
        ));
    }
}
