<?php
class CompressedRequestHandlerComponent extends Component
{
    /**
     * @throws Exception
     */
    public function initialize(Controller $controller)
    {
        if ($controller instanceof CakeErrorController) {
            return; // do not try to decode compressed content again for error controller
        }

        $contentEncoding = $_SERVER['HTTP_CONTENT_ENCODING'] ?? null;
        if (!empty($contentEncoding)) {
            if ($contentEncoding === 'zstd') {
                $controller->request->setInput($this->decodeZstdEncodedContent());
            } else if ($contentEncoding === 'br') {
                $controller->request->setInput($this->decodeBrotliEncodedContent());
            } else if ($contentEncoding === 'gzip') {
                $controller->request->setInput($this->decodeGzipEncodedContent());
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
        if (function_exists('zstd_uncompress')) {
            $supportedEncodings[] = 'zstd';
        }
        return $supportedEncodings;
    }

    /**
     * @return string
     * @throws Exception
     */
    private function decodeGzipEncodedContent()
    {
        if (function_exists('gzdecode')) {
            $decoded = gzdecode($this->input());
            if ($decoded === false) {
                throw new BadRequestException('Invalid compressed data.');
            }
            return $decoded;
        }
        throw new BadRequestException("This server doesn't support GZIP compressed requests.");
    }

    /**
     * @return string
     * @throws Exception
     */
    private function decodeBrotliEncodedContent()
    {
        if (function_exists('brotli_uncompress')) {
            $decoded = brotli_uncompress($this->input());
            if ($decoded === false) {
                throw new BadRequestException('Invalid compressed data.');
            }
            return $decoded;
        } else {
            throw new BadRequestException("This server doesn't support brotli compressed requests.");
        }
    }

    /**
     * @return string
     * @throws Exception
     */
    private function decodeZstdEncodedContent()
    {
        if (function_exists('zstd_uncompress')) {
            $decoded = zstd_uncompress($this->input());
            if ($decoded === false) {
                throw new BadRequestException('Invalid compressed data.');
            }
            return $decoded;
        } else {
            throw new BadRequestException("This server doesn't support zstd compressed requests.");
        }
    }

    /**
     * @return string
     * @throws Exception
     */
    private function input()
    {
        $input = file_get_contents('php://input');
        if ($input === false) {
            throw new Exception("Could not read input");
        }
        if (empty($input)) {
            throw new BadRequestException('Request data should be encoded, but request is empty.');
        }
        return $input;
    }
}
