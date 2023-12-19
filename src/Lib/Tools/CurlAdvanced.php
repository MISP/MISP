<?php

namespace App\Lib\Tools;

use Cake\Http\Client\Adapter\Curl;
use Cake\Http\Client\Exception\ClientException;
use Cake\Http\Client\Exception\NetworkException;
use Cake\Http\Client\Exception\RequestException;
use Psr\Http\Message\RequestInterface;

class CurlAdvanced extends Curl 
{

    /**
     * @inheritDoc
     */
    public function getCertificateChain(RequestInterface $request, array $options): array
    {
        if (!extension_loaded('curl')) {
            throw new ClientException('curl extension is not loaded.');
        }

        $ch = curl_init();
        $options['curl'] = [
            CURLOPT_CERTINFO => true,
            // CURLOPT_VERBOSE => true,
            CURLOPT_NOBODY => true,
        ];
     
        $options = $this->buildOptions($request, $options);
        curl_setopt_array($ch, $options);

        /** @var string|false $body */
        $body = $this->exec($ch);
        if ($body === false) {
            $errorCode = curl_errno($ch);
            $error = curl_error($ch);
            curl_close($ch);

            $message = "cURL Error ({$errorCode}) {$error}";
            $errorNumbers = [
                CURLE_FAILED_INIT,
                CURLE_URL_MALFORMAT,
                CURLE_URL_MALFORMAT_USER,
            ];
            if (in_array($errorCode, $errorNumbers, true)) {
                throw new RequestException($message, $request);
            }
            throw new NetworkException($message, $request);
        }
        $certinfo = curl_getinfo($ch, CURLINFO_CERTINFO);
        curl_close($ch);

        return $certinfo;
    }
}
