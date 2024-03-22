<?php
class CompressedRequestHandlerComponent extends Component
{
    public function startup(Controller $controller)
    {
        $contentEncoding = $_SERVER['HTTP_CONTENT_ENCODING'] ?? null;
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
            $input = $controller->request->input();
            if (empty($input)) {
                throw new BadRequestException('Request data should be gzip encoded, but request is empty.');
            }
            $decoded = gzdecode($input);
            if ($decoded === false) {
                throw new BadRequestException('Invalid compressed data.');
            }
            return $decoded;
        }
        throw new BadRequestException("This server doesn't support GZIP compressed requests.");
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
