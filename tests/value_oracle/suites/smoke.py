"""Minimal live suite proving the record/compare cycle and both API keys."""

from core import Case, ids_at, json_without

RESTSEARCH = '/attributes/restSearch'


def cases(config):
    exact = {'returnFormat': 'json', 'value': '8.8.8.8'}
    return [
        Case('version', '/servers/getVersion.json',
             json_without(drop=['uuid']),
             description='instance version and sync permissions'),
        Case('value_exact_admin', RESTSEARCH,
             ids_at('response.Attribute[].id'),
             method='POST', body=exact,
             description='exact value lookup as site admin'),
        Case('value_exact_lesser', RESTSEARCH,
             ids_at('response.Attribute[].id'),
             method='POST', body=exact, user='lesser',
             description='exact value lookup as a lesser org user'),
    ]
