<?php
App::uses('DecompressTool', 'Tools');
App::uses('DecompressLimitException', 'Tools');

class CompressedRequestHandlerComponent extends Component
{
    /**
     * Nothing is decoded here: initialize() runs before the user is authenticated.
     * AppController::beforeFilter() calls decodeRequest() or rejectEncodedRequest().
     */
    public function initialize(Controller $controller)
    {
    }

    /**
     * To be called for authenticated users only, after their memory_limit is applied.
     *
     * @param Controller $controller
     * @throws Exception
     */
    public function decodeRequest(Controller $controller)
    {
        if ($controller instanceof CakeErrorController) {
            return; // do not try to decode compressed content again for error controller
        }

        $contentEncoding = $this->contentEncoding();
        if (empty($contentEncoding)) {
            return;
        }
        if (!in_array($contentEncoding, ['zstd', 'br', 'gzip'], true)) {
            throw new BadRequestException("Unsupported content encoding '$contentEncoding'.");
        }
        $names = ['zstd' => 'zstd', 'br' => 'brotli', 'gzip' => 'GZIP'];
        if (!in_array($contentEncoding, DecompressTool::supportedEncodings(), true)) {
            throw new BadRequestException("This server doesn't support {$names[$contentEncoding]} compressed requests.");
        }

        $input = $controller->request->input();
        if ($input === false || $input === null || $input === '') {
            throw new BadRequestException('Request data should be encoded, but request is empty.');
        }
        try {
            $decoded = DecompressTool::decode($contentEncoding, $input, $this->maxDecompressedSize());
        } catch (DecompressLimitException $e) {
            throw new HttpException('Decompressed request body is larger than the allowed maximum.', 413);
        } catch (InvalidArgumentException $e) {
            throw new BadRequestException('Invalid compressed data.');
        }
        $controller->request->setInput($decoded);
    }

    /**
     * To be called for requests that are not authenticated.
     *
     * @param Controller $controller
     * @throws BadRequestException
     */
    public function rejectEncodedRequest(Controller $controller)
    {
        if ($controller instanceof CakeErrorController) {
            return;
        }
        if (!empty($this->contentEncoding())) {
            throw new BadRequestException('Compressed requests are accepted only from authenticated users.');
        }
    }

    /**
     * @return array
     */
    public function supportedEncodings()
    {
        return DecompressTool::supportedEncodings();
    }

    /**
     * @return int|null Null for no limit
     */
    public function maxDecompressedSize()
    {
        return DecompressTool::limit();
    }

    /**
     * @return string|null
     */
    private function contentEncoding()
    {
        return $_SERVER['HTTP_CONTENT_ENCODING'] ?? null;
    }
}
