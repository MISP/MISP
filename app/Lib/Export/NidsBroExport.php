<?php

App::uses('NidsExport', 'Export');

class NidsBroExport extends NidsExport
{

	public function export($items, $startSid, $format = "suricata", $continue = false)
	{
		// set the specific format
		$this->format = "bro";
		// call the generic function
		return parent::export($items, $startSid, $format, $continue);
	}

	// below overwrite functions from NidsExport
	public function ipDstRule($ruleFormat, $attribute, &$sid)
	{
		$overruled = $this->checkWhitelist($attribute['value']);
		$attribute['value'] = NidsExport::replaceIllegalChars($attribute['value']);  // substitute chars not allowed in rule
		$this->rules[] = sprintf($ruleFormat,
		($overruled) ? '#OVERRULED BY WHITELIST# ' :
			$attribute['value'],	// dst_ip
			'Intel:ADDR',	// type
			'T',	// meta.do_notice
			'-'  // meta.if_in
		);
	}

	public function ipSrcRule($ruleFormat, $attribute, &$sid)
	{
		$overruled = $this->checkWhitelist($attribute['value']);
		$attribute['value'] = NidsExport::replaceIllegalChars($attribute['value']);  // substitute chars not allowed in rule
		$this->rules[] = sprintf($ruleFormat,
			($overruled) ? '#OVERRULED BY WHITELIST# ' :
			$attribute['value'],	// dst_ip
			'Intel:ADDR',	// type
			'T',	// meta.do_notice
			'-'  // meta.if_in
		);
	}

	public function emailSrcRule($ruleFormat, $attribute, &$sid)
	{
		$overruled = $this->checkWhitelist($attribute['value']);
		$attribute['value'] = NidsExport::replaceIllegalChars($attribute['value']);  // substitute chars not allowed in rule
		$this->rules[] = sprintf($ruleFormat,
			($overruled) ? '#OVERRULED BY WHITELIST# ' :
			$attribute['value'],	// dst_ip
			'Intel:EMAIL',  // type
			'T',	// meta.do_notice
			'-'  // meta.if_in
		);
	}

	public function emailDstRule($ruleFormat, $attribute, &$sid)
	{
		$overruled = $this->checkWhitelist($attribute['value']);
		$attribute['value'] = NidsExport::replaceIllegalChars($attribute['value']);  // substitute chars not allowed in rule
		$this->rules[] = sprintf($ruleFormat,
			($overruled) ? '#OVERRULED BY WHITELIST# ' :
			$attribute['value'],	// dst_ip
			'Intel:EMAIL',  // type
			'T',	// meta.do_notice
			'-'  // meta.if_in
		);
	}

	public function emailSubjectRule($ruleFormat, $attribute, &$sid)
	{
	// Nothing to return, there is no clear mapping to Bro intel
	}

	public function emailAttachmentRule($ruleFormat, $attribute, &$sid)
	{
		$overruled = $this->checkWhitelist($attribute['value']);
		$attribute['value'] = NidsExport::replaceIllegalChars($attribute['value']);  // substitute chars not allowed in rule
		$this->rules[] = sprintf($ruleFormat,
			($overruled) ? '#OVERRULED BY WHITELIST# ' :
			$attribute['value'],	// dst_ip
			'Intel:FILE_NAME',  // type
			'T',	// meta.do_notice
			'-'  // meta.if_in
		);
	}

	public function hostnameRule($ruleFormat, $attribute, &$sid)
	{
		$overruled = $this->checkWhitelist($attribute['value']);
		$attribute['value'] = NidsExport::replaceIllegalChars($attribute['value']);  // substitute chars not allowed in rule
		$this->rules[] = sprintf($ruleFormat,
			($overruled) ? '#OVERRULED BY WHITELIST# ' :
			$attribute['value'],	// dst_ip
			'Intel:DOMAIN', // type
			'T',	// meta.do_notice
			'-'  // meta.if_in
		);
	}

	public function domainRule($ruleFormat, $attribute, &$sid)
	{
		$overruled = $this->checkWhitelist($attribute['value']);
		$attribute['value'] = NidsExport::replaceIllegalChars($attribute['value']);  // substitute chars not allowed in rule
		$this->rules[] = sprintf($ruleFormat,
			($overruled) ? '#OVERRULED BY WHITELIST# ' :
			$attribute['value'],	// dst_ip
			'Intel:DOMAIN', // type
			'T',	// meta.do_notice
			'-'  // meta.if_in
		);
	}

	public function urlRule($ruleFormat, $attribute, &$sid)
	{
		$overruled = $this->checkWhitelist($attribute['value']);
		$attribute['value'] = NidsExport::replaceIllegalChars($attribute['value']);  // substitute chars not allowed in rule
		$attribute['value'] = preg_replace('#^https?://#', '', $attribute['value']);
		$this->rules[] = sprintf($ruleFormat,
			($overruled) ? '#OVERRULED BY WHITELIST# ' :
			$attribute['value'],	// dst_ip
			'Intel:URL',	// type
			'T',	// meta.do_notice
			'-'  // meta.if_in
		);
	}

	public function userAgentRule($ruleFormat, $attribute, &$sid)
	{
		$overruled = $this->checkWhitelist($attribute['value']);
		$attribute['value'] = NidsExport::replaceIllegalChars($attribute['value']);  // substitute chars not allowed in rule
		$this->rules[] = sprintf($ruleFormat,
			($overruled) ? '#OVERRULED BY WHITELIST# ' :
			$attribute['value'],	// dst_ip
			'Intel:SOFTWARE',	// type
			'T',	// meta.do_notice
			'-'  // meta.if_in
		);
	}

	public function snortRule($ruleFormat, $attribute, &$sid, $ruleFormatMsg, $ruleFormatReference)
	{
	//Nothing to export
	}
}