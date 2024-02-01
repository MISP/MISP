<?php

namespace App\Controller\Component;

use Cake\Controller\Component;
use Cake\Http\Exception\BadRequestException;
use Cake\Event\EventInterface;
use Cake\Controller\Controller;

class CompressedRequestHandlerComponent extends Component
{
    public function startup(EventInterface $event)
    {
        $controller = $this->getController();
        $contentEncoding = $_SERVER['HTTP_CONTENT_ENCODING'] ?? null;

        if ($contentEncoding === 'application/json') {
            return;
        }
        if (!empty($contentEncoding)) {
            if ($contentEncoding === 'br') {
                $controller->request->setInput($this->decodeBrotliEncodedContent($controller));
            } else if ($contentEncoding === 'gzip') {
                $controller->request->setInput($this->decodeGzipEncodedContent($controller));
            } else {
                throw new BadRequestException("Unsupported content encoding '$contentEncoding'.");
            }
        }
    }

    /**
     * @return array
     */
    public function supportedEncodings()
    {
        $supportedEncodings = [];
        if (function_exists('gzdecode')) {
            $supportedEncodings[] = 'gzip';
        }
        if (function_exists('brotli_uncompress')) {
            $supportedEncodings[] = 'br';
        }
        return $supportedEncodings;
    }

    /**
     * @return string
     * @throws Exception
     */
    private function decodeGzipEncodedContent(Controller $controller)
    {
        if (function_exists('gzdecode')) {
            $decoded = gzdecode($controller->request->input());
            if ($decoded === false) {
                throw new BadRequestException('Invalid compressed data.');
            }
            return $decoded;
        } else {
            throw new BadRequestException("This server doesn't support GZIP compressed requests.");
        }
    }

    /**
     * @param Controller $controller
     * @return string
     * @throws Exception
     */
    private function decodeBrotliEncodedContent(Controller $controller)
    {
        if (function_exists('brotli_uncompress')) {
            $decoded = brotli_uncompress($controller->request->input());
            if ($decoded === false) {
                throw new BadRequestException('Invalid compressed data.');
            }
            return $decoded;
        } else {
            throw new BadRequestException("This server doesn't support brotli compressed requests.");
        }
    }
}
