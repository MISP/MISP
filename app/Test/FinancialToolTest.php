<?php
require_once __DIR__ . '/../Lib/Tools/FinancialTool.php';

use PHPUnit\Framework\TestCase;

class FinancialToolTest extends TestCase
{
    public function testValidateBtc(): void
    {
        $financialTool = new FinancialTool();
        $this->assertTrue($financialTool->validateBTC('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'), 'P2PKH');
        $this->assertTrue($financialTool->validateBTC('3GRdnTq18LyNveWa1gQJcgp8qEnzijv5vR'), 'P2SH');
        $this->assertTrue($financialTool->validateBTC('bc1qnkyhslv83yyp0q0suxw0uj3lg9drgqq9c0auzc'), 'P2WPKH');
        $this->assertTrue($financialTool->validateBTC('bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq'), 'P2WPKH');
        $this->assertTrue($financialTool->validateBTC('bc1qc7slrfxkknqcq2jevvvkdgvrt8080852dfjewde450xdlk4ugp7szw5tk9'), 'P2WPKH');
    }
}
