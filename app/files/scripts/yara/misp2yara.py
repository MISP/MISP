from yaratemplate import YaraRuleTemplate, YaraTemplateException
import uuid


# =========================== CORE EXPORTERS ===================================
def mispevent2yara(event, options={}):
    default_opts = {
        'chaining_op': 'or',
        'display_attr_uuids': False,
        'max_attrs_per_rule': 1000,
        'event_uuid_only': True
    }
    default_opts.update(options)
    opts = default_opts
    if not event['Attribute']:
        return []
    generated, asis_valid, asis_broken = mispattrs2yara(event['Attribute'], opts)
    for rule_index, r in enumerate(generated + asis_valid):
        if not r.loaded_from_source and r.attr_count() > 1:
            rulename = 'MISP_EVENT_{}_PART{}'.format(event['uuid'].replace('-', '_'), rule_index+1)
            r.set_name(rulename)
        r.add_meta('MISP_EVENT_UUID', event['uuid'])
        r.add_meta('MISP_EVENT_INFO', event['info'])
    return generated, asis_valid, asis_broken


def mispobject2yara(obj):
    pass


def mispattrs2yara(attrs_array, options={}):
    if not attrs_array:
        return []
    opts = {
        'chaining_op': 'or',
        'max_attrs_per_rule': 1
    }
    opts.update(options)
    generated_rules = []
    asis_valid_rules = []
    asis_broken_rules = []
    current_rule = MISPRuleTemplate()
    for i, attr in enumerate(attrs_array):
        if attr['type'] == 'yara':
            try:
                yara_rules = MISPRuleTemplate.from_yara_attr(attr)
                asis_valid_rules += yara_rules
            except YaraTemplateException as e:
                comment = '/*            MISP EXPORT COMMENT\n'
                comment += '    MISP_UUID: {}\n'.format(attr['uuid'])
                comment += '    {}\n'.format(str(e))
                comment += '*/\n'
                commented_attr = '{}{}'.format(comment, attr['value'])
                asis_broken_rules.append(commented_attr)
        else:
            current_rule.add_attribute(attr, opts)
        last_attr_reached = i == len(attrs_array)-1
        max_size_reached = current_rule.attr_count() >= opts['max_attrs_per_rule']
        if last_attr_reached or max_size_reached:
            # if rule has "strings" section, generate the corresponding "condition"
            if current_rule.strings:
                if opts['chaining_op'] == 'or':
                    current_rule.or_condition('any of them')
                elif opts['chaining_op'] == 'and':
                    current_rule.and_condition('all of them')
            # if rule has "condition" section, add meta, rename and add it to results, else discard it
            if current_rule.condition:
                generated_rules.append(current_rule)
            current_rule = MISPRuleTemplate()
    return generated_rules, asis_valid_rules, asis_broken_rules


# =========================== ATTR HANDLERS CORE ===============================
class MISPRuleTemplate(YaraRuleTemplate):

    def __init__(self, rulename=None):
        super().__init__(rulename)
        self._attributes_count = 0

    @classmethod
    def from_yara_attr(cls, mispattr):
        rules = cls.from_source(mispattr['value'])
        for rule in rules:
            rule._enrich(mispattr)
        return rules

    def add_attribute(self, mispattr, options):
        opts = {
            'chaining_op': 'or',
        }
        opts.update(options)
        self._handle(mispattr, opts)
        self._attributes_count += 1
        event_only = False
        if 'event_uuid_only' in opts and opts['event_uuid_only']:
            event_only = True
        self._enrich(mispattr, event_uuid_only=event_only)
        self._generate_name(mispattr)
        return self

    def _enrich(self, attr, event=None, event_uuid_only=False):
        if not event and 'Event' in attr:
            event = attr['Event']
        # META:
        #   attribute uuids
        if not event_uuid_only:
            uuid_meta = '{} ({})'.format(attr['uuid'], attr['type'])
            self.add_meta('MISP_UUID', uuid_meta)
        #   event uuids
        if event:
            self.add_meta('MISP_EVENT_UUID', event['uuid'])
            self.add_meta('MISP_EVENT_INFO', event['info'])
        # other META and TAGS:
        if self.loaded_from_source:
            self.add_tag('as_is')
            if self.autofixed:
                self.add_tag('repaired')
                origin_msg = 'Loaded from a corrupted Yara attribute, '\
                            + 'automatically repaired.'\
                            + 'Some comments may have been removed by parser. '\
                            + 'Rule may be unreliable.'
                self.add_meta('MISP_ORIGIN', origin_msg)
                self.add_meta('MISP_FIX_NOTES', self.autofixed_comment)
            else:
                self.add_tag('valid')
                validity_msg = 'Loaded as-is from a Yara attribute. ' \
                             + 'Some comments may have been removed by parser.'
                self.add_meta('MISP_ORIGIN', validity_msg)
        else:
            self.add_tag('generated')
            self.add_meta('MISP_ORIGIN', 'Automatically generated ' \
                                                + 'from non-Yara attribute(s)')
        return self

    def _generate_name(self, attr):
        if self.loaded_from_source:
            pass
        elif self._attributes_count == 1:
            name = 'MISP_ATTRIBUTE_{}'.format(attr['uuid'])
            self.set_name(name)
        else:
            rand_id = str(uuid.uuid4()).replace('-', '')
            name = 'MISP_MULTI_ATTRIBUTES_{}'.format(rand_id)
            self.set_name(name)
        return self

    def attr_count(self):
        return self._attributes_count

    def _handle(self, attr, opts):
        attr_type = attr['type']
        handler = self._get_type_handler(attr_type)
        if handler:
            handler(attr, opts)
        return self

# =========================== ATTR HANDLERS ====================================
    def _get_type_handler(self, attr_type):
        handlers = {
            'md5': self._md5,
            'sha1': self._sha1,
            'sha256': self._sha256,
            # 'filename': self._filename, # unsupported by yara
            'filename|md5': self._filename_md5,
            'filename|sha1': self._filename_sha1,
            'filename|sha256': self._filename_sha256,
            'ip-src': self._ip_src,
            'ip-dst': self._ip_dst,
            'hostname': self._hostname,
            'domain': self._domain,
            'domain|ip': self._domain_ip,
            'email-src': self._email_src,
            'email-dst': self._email_dst,
            'email-subject': self._email_subject,
            'email-body': self._email_body,
            'url': self._url,
            'regkey': self._regkey,
            'regkey|value': self._regkey_value,
            'pattern-in-file': self._pattern_in_file,
            'pattern-in-traffic': self._pattern_in_traffic,
            'pattern-in-memory': self._pattern_in_memory,
            # 'yara': self._yara, # specific case, see _yara2yaras()
            'cookie': self._cookie,
            'vulnerability': self._vulnerability,
            'text': self._text,
            'hex': self._hex,
            'named pipe': self._named_pipe,
            'mutex': self._mutex,
            'btc': self._btc,
            'xmr': self._xmr,
            'uri': self._uri,
            # 'authentihash': self._authentihash, # unsupported by yara
            # 'ssdeep': self._ssdeep, # unsupported by yara
            'imphash': self._imphash,
            # 'pehash': self._pehash, # unsupported by yara
            # 'impfuzzy': self._impfuzzy, # unsupported by yara
            # 'sha224': self._sha224, # unsupported by yara
            # 'sha384': self._sha384, # unsupported by yara
            # 'sha512': self._sha512, # unsupported by yara
            # 'sha512/224': self._sha512_224, # unsupported by yara
            # 'sha512/256': self._sha512_256, # unsupported by yara
            # 'tlsh': self._tlsh, # unsupported by yara
            # 'cdhash': self._cdhash, # unsupported by yara
            # 'filename|authentihash': self._filename_authentihash, # unsupported by yara
            # 'filename|ssdeep': self._filename_ssdeep, # unsupported by yara
            'filename|imphash': self._filename_imphash,
            # 'filename|impfuzzy': self._filename_impfuzzy, # unsupported by yara
            # 'filename|pehash': self._filename_pehash, # unsupported by yara
            # 'filename|sha224': self._filename_sha224, # unsupported by yara
            # 'filename|sha384': self._filename_sha384, # unsupported by yara
            # 'filename|sha512': self._filename_sha512, # unsupported by yara
            # 'filename|sha512/224': self._filename_sha512_224, # unsupported by yara
            # 'filename|sha512/256': self._filename_sha512_256, # unsupported by yara
            # 'filename|tlsh': self._filename_tlsh, # unsupported by yara
            'windows-scheduled-task': self._windows_scheduled_task,
            'windows-service-name': self._windows_service_name,
            'windows-service-displayname': self._windows_service_displayname,
            # 'x509-fingerprint-sha1': self._x509_fingerprint_sha1, # TODO check if doable
            # 'x509-fingerprint-md5': self._x509_fingerprint_md5, # TODO check if doable
            # 'x509-fingerprint-sha256': self._x509_fingerprint_sha256, # TODO check if doable
            # 'size-in-bytes': self._size_in_bytes, # too many false positives
            'ip-dst|port': self._ip_dst_port,
            'ip-src|port': self._ip_src_port,
            'hostname|port': self._hostname_port,
            'email-dst-display-name': self._email_dst_display_name,
            'email-src-display-name': self._email_src_display_name,
            'email-header': self._email_header,
            'email-reply-to': self._email_reply_to,
            'email-x-mailer': self._email_x_mailer,
            'email-mime-boundary': self._email_mime_boundary,
            'email-thread-index': self._email_thread_index,
            'email-message-id': self._email_message_id,
            'github-username': self._github_username,
            'github-repository': self._github_repository,
            'github-organisation': self._github_organisation,
            'mobile-application-id': self._mobile_application_id,

            'user-agent': self._user_agent,
        }
        if attr_type in handlers:
            return handlers[attr_type]
        else:
            return None

    def __generic_string(self, value, opts):
        self.strings_text(None, value,
                          escape_newlines=True,
                          nocase=False,
                          ascii=True,
                          wide=True,
                          xor=False,
                          fullword=False)
        return self

    def _md5(self, attr, opts):
        filehash = attr['value']
        self.add_module_dependency('hash')
        self.or_condition('hash.md5(0, filesize) == "{}"'.format(filehash))
        return self

    def _sha1(self, attr, opts):
        filehash = attr['value']
        self.add_module_dependency('hash')
        self.or_condition('hash.sha1(0, filesize) == "{}"'.format(filehash))
        return self

    def _sha256(self, attr, opts):
        filehash = attr['value']
        self.add_module_dependency('hash')
        self.or_condition('hash.sha256(0, filesize) == "{}"'.format(filehash))
        return self

    # def _filename(self, attr, opts):
    #     self.__generic_string(attr['value'], opts)
    #     return self

    def _filename_md5(self, attr, opts):
        filename, _, filehash = attr['value'].rpartition('|')
        self.add_module_dependency('hash')
        self.or_condition('hash.md5(0, filesize) == "{}"'.format(filehash))
        return self

    def _filename_sha1(self, attr, opts):
        filename, _, filehash = attr['value'].rpartition('|')
        self.add_module_dependency('hash')
        self.or_condition('hash.sha1(0, filesize) == "{}"'.format(filehash))
        return self

    def _filename_sha256(self, attr, opts):
        filename, _, filehash = attr['value'].rpartition('|')
        self.add_module_dependency('hash')
        self.or_condition('hash.sha256(0, filesize) == "{}"'.format(filehash))
        return self

    def _ip_src(self, attr, opts):
        self.__generic_string(attr['value'], opts)
        return self

    def _ip_dst(self, attr, opts):
        self.__generic_string(attr['value'], opts)
        return self

    def _hostname(self, attr, opts):
        self.__generic_string(attr['value'], opts)
        return self

    def _domain(self, attr, opts):
        self.__generic_string(attr['value'], opts)
        return self

    def _domain_ip(self, attr, opts):
        domain, _, ip = attr['value'].rpartition('|')
        self.__generic_string(domain, opts)
        self.__generic_string(ip, opts)
        return self

    def _email_src(self, attr, opts):
        self.__generic_string(attr['value'], opts)
        return self

    def _email_dst(self, attr, opts):
        self.__generic_string(attr['value'], opts)
        return self

    def _email_subject(self, attr, opts):
        self.__generic_string(attr['value'], opts)
        return self

    def _email_body(self, attr, opts):
        self.__generic_string(attr['value'], opts)
        return self

    def _url(self, attr, opts):
        self.__generic_string(attr['value'], opts)
        return self

    def _regkey(self, attr, opts):
        self.__generic_string(attr['value'], opts)
        return self

    def _regkey_value(self, attr, opts):
        regkey, _, regvalue = attr['value'].rpartition('|')
        self.__generic_string(regkey, opts)
        self.__generic_string(regvalue, opts)
        return self

    def _pattern_in_file(self, attr, opts):
        self.__generic_string(attr['value'], opts)
        return self

    def _pattern_in_traffic(self, attr, opts):
        self.__generic_string(attr['value'], opts)
        return self

    def _pattern_in_memory(self, attr, opts):
        self.__generic_string(attr['value'], opts)
        return self

    def _yara(self, attr, opts):
        self.__generic_string(attr['value'], opts)
        return self

    def _cookie(self, attr, opts):
        self.__generic_string(attr['value'], opts)
        return self

    def _vulnerability(self, attr, opts):
        self.__generic_string(attr['value'], opts)
        return self

    def _text(self, attr, opts):
        self.__generic_string(attr['value'], opts)
        return self

    def _hex(self, attr, opts):
        self.strings_hex(None, attr['value'])
        return self

    def _named_pipe(self, attr, opts):
        self.__generic_string(attr['value'], opts)
        return self

    def _mutex(self, attr, opts):
        self.__generic_string(attr['value'], opts)
        return self

    def _btc(self, attr, opts):
        self.__generic_string(attr['value'], opts)
        return self

    def _xmr(self, attr, opts):
        self.__generic_string(attr['value'], opts)
        return self

    def _uri(self, attr, opts):
        self.__generic_string(attr['value'], opts)
        return self

    # def _authentihash(self, attr, opts):
    #     self.__generic_string(attr['value'], opts)
    #     return self
    #
    # def _ssdeep(self, attr, opts):
    #     self.__generic_string(attr['value'], opts)
    #     return self

    def _imphash(self, attr, opts):
        filehash = attr['value']
        self.add_module_dependency('pe')
        self.or_condition('pe.imphash() == "{}"'.format(filehash))
        return self

    def _filename_imphash(self, attr, opts):
        filename, _, filehash = attr['value'].rpartition('|')
        self.add_module_dependency('pe')
        self.or_condition('pe.imphash() == "{}"'.format(filehash))
        return self

    # def _filename_impfuzzy(self, attr, opts):
    #     self.__generic_string(attr['value'], opts)
    #     return self
    #
    # def _filename_pehash(self, attr, opts):
    #     self.__generic_string(attr['value'], opts)
    #     return self
    #
    # def _filename_sha224(self, attr, opts):
    #     self.__generic_string(attr['value'], opts)
    #     return self
    #
    # def _filename_sha384(self, attr, opts):
    #     self.__generic_string(attr['value'], opts)
    #     return self
    #
    # def _filename_sha512(self, attr, opts):
    #     self.__generic_string(attr['value'], opts)
    #     return self
    #
    # def _filename_sha512_224(self, attr, opts):
    #     self.__generic_string(attr['value'], opts)
    #     return self
    #
    # def _filename_sha512_256(self, attr, opts):
    #     self.__generic_string(attr['value'], opts)
    #     return self
    #
    # def _filename_tlsh(self, attr, opts):
    #     self.__generic_string(attr['value'], opts)
    #     return self

    def _windows_scheduled_task(self, attr, opts):
        self.__generic_string(attr['value'], opts)
        return self

    def _windows_service_name(self, attr, opts):
        self.__generic_string(attr['value'], opts)
        return self

    def _windows_service_displayname(self, attr, opts):
        self.__generic_string(attr['value'], opts)
        return self

    # TODO: check if that can be implemented
    # def _x509_fingerprint_sha1(self, attr, opts):
    #     self.__generic_string(attr['value'], opts)
    #     return self
    #
    # def _x509_fingerprint_md5(self, attr, opts):
    #     self.__generic_string(attr['value'], opts)
    #     return self
    #
    # def _x509_fingerprint_sha256(self, attr, opts):
    #     self.__generic_string(attr['value'], opts)
    #     return self

    # TODO: too many false-positives but could be OK in objects
    # def _size_in_bytes(self, attr, opts):
    #     self.__generic_string(attr['value'], opts)
    #     return self
    #

    # likely false positives on ports, also can't guess ip:port format.
    # Ignoring port
    def _ip_dst_port(self, attr, opts):
        ip, _, port = attr['value'].rpartition('|')
        self.__generic_string(ip, opts)
        return self

    def _ip_src_port(self, attr, opts):
        ip, _, port = attr['value'].rpartition('|')
        self.__generic_string(ip, opts)
        return self

    def _hostname_port(self, attr, opts):
        host, _, port = attr['value'].rpartition('|')
        self.__generic_string(host, opts)
        return self

    def _email_dst_display_name(self, attr, opts):
        self.__generic_string(attr['value'], opts)
        return self

    def _email_src_display_name(self, attr, opts):
        self.__generic_string(attr['value'], opts)
        return self

    def _email_header(self, attr, opts):
        self.__generic_string(attr['value'], opts)
        return self

    def _email_reply_to(self, attr, opts):
        self.__generic_string(attr['value'], opts)
        return self

    def _email_x_mailer(self, attr, opts):
        self.__generic_string(attr['value'], opts)
        return self

    def _email_mime_boundary(self, attr, opts):
        self.__generic_string(attr['value'], opts)
        return self

    def _email_thread_index(self, attr, opts):
        self.__generic_string(attr['value'], opts)
        return self

    def _email_message_id(self, attr, opts):
        self.__generic_string(attr['value'], opts)
        return self

    def _github_username(self, attr, opts):
        self.__generic_string(attr['value'], opts)
        return self

    def _github_repository(self, attr, opts):
        self.__generic_string(attr['value'], opts)
        return self

    def _github_organisation(self, attr, opts):
        self.__generic_string(attr['value'], opts)
        return self

    def _mobile_application_id(self, attr, opts):
        self.__generic_string(attr['value'], opts)
        return self

    def _user_agent(self, attr, opts):
        self.__generic_string(attr['value'], opts)
        return self
