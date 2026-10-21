"""Explicit publication schemas for captured chain responses.

Transport locations, headers, messages, log strings and identity content are not
part of these schemas. Unknown transport/request fields fail closed. Extra
response fields are dropped only by the named schema, never copied recursively.
Projected bytes have new hashes and are not authenticated original responses.
"""
import base64
import json
import struct
from decimal import Decimal
from .core import address, decode58, encode58, loads, require, sha


def exact_json(value):
    if isinstance(value, Decimal):
        require(value.is_finite(), 'Nonfinite number')
        return str(value)
    if isinstance(value, dict):
        return '{' + ','.join(json.dumps(k, ensure_ascii=False) + ':' + exact_json(v)
                              for k, v in sorted(value.items())) + '}'
    if isinstance(value, list):
        return '[' + ','.join(exact_json(v) for v in value) + ']'
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(',', ':'))


def encode(value):
    return (exact_json(value) + '\n').encode()


def select(value, allowed, required=()):
    require(isinstance(value, dict), 'Expected object')
    require(set(required) <= set(value), 'Missing required schema field')
    return {key: value[key] for key in allowed if key in value}


def strict(value, allowed, required=()):
    result = select(value, allowed, required)
    require(set(value) <= set(allowed), 'Unknown field in strict publication schema')
    return result


def project_request(value):
    result = strict(value, {'jsonrpc', 'id', 'method', 'params'}, {'method', 'params'})
    require(result.get('jsonrpc', '2.0') == '2.0' and
            ('id' not in result or type(result['id']) is int), 'Unsupported JSON-RPC envelope')
    require(result['method'] in METHODS, 'Unsupported captured RPC method')
    # Parameters contain addresses, filters, cursors and collection options;
    # they have a separate scalar scanner, and never contain transport headers.
    allowed = {
        'encoding', 'commitment', 'minContextSlot', 'withContext', 'filters', 'dataSlice',
        'dataSize', 'memcmp', 'offset', 'length', 'bytes', 'limit', 'paginationKey', 'paginationToken',
        'sortOrder', 'transactionDetails', 'maxSupportedTransactionVersion', 'slot', 'gte', 'gt',
        'lte', 'lt', 'status', 'blockTime', 'before', 'until', 'page', 'cursor', 'ownerAddress',
        'authorityAddress', 'grouping', 'creatorAddress', 'creatorVerified', 'collection', 'frozen',
        'burnt', 'tokenType', 'options', 'showFungible', 'showNativeBalance', 'showZeroBalance',
        'showCollectionMetadata', 'showUnverifiedCollections', 'showGrandTotal', 'sortBy',
        'sortDirection', 'mint', 'programId', 'jsonUri', 'supply', 'supplyMint', 'displayOptions',
        'compressed', 'interface', 'changedSinceSlot', 'ids',
    }
    def walk(item):
        if isinstance(item, dict):
            require(set(item) <= allowed, 'Unknown RPC parameter field')
            return {key: walk(child) for key, child in item.items()}
        if isinstance(item, list):
            return [walk(child) for child in item]
        require(item is None or type(item) in (str, int, bool, float), 'Invalid RPC parameter')
        return item
    result['params'] = walk(result['params'])
    return result


def context(value):
    result = select(value, {'slot', 'apiVersion'}, {'slot'})
    integer(result['slot'])
    if 'apiVersion' in result:
        require(isinstance(result['apiVersion'], str) and
                all(part.isdigit() for part in result['apiVersion'].split('.')), 'Invalid RPC version')
    return result


def redact_token_metadata(raw, clear_fingerprint=False):
    """Keep fingerprint fields and authorities, remove arbitrary additional metadata.

    The Token-2022 metadata extension is a borsh header plus three strings and
    an arbitrary vector of string pairs. Pair contents are not eligibility facts.
    Return a decoded-presence flag separately; new bytes carry an empty vector.
    """
    if len(raw) < 166 or raw[165] != 1:
        return raw, False
    offset, output, redacted = 166, bytearray(raw[:166]), False
    while offset < len(raw):
        if not any(raw[offset:]):
            output.extend(raw[offset:])
            break
        require(offset + 4 <= len(raw), 'Truncated token extension')
        kind, length = struct.unpack_from('<HH', raw, offset)
        offset += 4
        require(offset + length <= len(raw), 'Truncated token extension body')
        body = raw[offset:offset + length]
        offset += length
        if kind == 19:
            require(len(body) >= 64, 'Truncated token metadata')
            end = 64
            for _ in range(3):
                require(end + 4 <= len(body), 'Truncated token metadata string')
                size = int.from_bytes(body[end:end + 4], 'little')
                end += 4 + size
                require(end <= len(body), 'Truncated token metadata string')
            require(end + 4 <= len(body), 'Truncated additional metadata')
            count = int.from_bytes(body[end:end + 4], 'little')
            cursor = end + 4
            for _ in range(count * 2):
                require(cursor + 4 <= len(body), 'Truncated additional metadata pair')
                size = int.from_bytes(body[cursor:cursor + 4], 'little')
                cursor += 4 + size
                require(cursor <= len(body), 'Truncated additional metadata pair')
            require(cursor == len(body), 'Unknown trailing token metadata')
            if clear_fingerprint:
                body = body[:64] + bytes(16)
                redacted = True
            elif count:
                body = body[:end] + bytes(4)
                redacted = True
        output.extend(struct.pack('<HH', kind, len(body)))
        output.extend(body)
    return bytes(output), redacted


def account(value, strip_metadata=False):
    if value is None:
        return None
    result = select(value, {'data', 'lamports', 'owner', 'executable', 'rentEpoch', 'space'},
                    {'data', 'lamports', 'owner', 'executable'})
    address(result['owner'])
    data = result['data']
    if isinstance(data, list):
        require(len(data) == 2 and data[1] == 'base64', 'Unsupported account encoding')
        raw = base64.b64decode(data[0], validate=True)
        if strip_metadata and result['owner'] == 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb':
            raw, _ = redact_token_metadata(raw, clear_fingerprint=strip_metadata == 'all')
            result['data'] = [base64.b64encode(raw).decode(), 'base64']
            if 'space' in result:
                result['space'] = len(raw)
    else:
        result['data'] = select(data, {'program', 'parsed', 'space'}, {'parsed'})
        parsed = select(data['parsed'], {'type', 'info'}, {'info'})
        parsed['info'] = select(parsed['info'], {'mint', 'owner', 'tokenAmount', 'state', 'isNative',
                                               'rentExemptReserve', 'delegate', 'delegatedAmount',
                                               'closeAuthority', 'decimals', 'supply', 'isInitialized',
                                               'mintAuthority', 'freezeAuthority'}, {'owner'}
                               if parsed.get('type') == 'account' else ())
        result['data']['parsed'] = parsed
        require(parsed.get('type') in ('account', 'mint', 'multisig'), 'Unsupported parsed account type')
        info = parsed['info']
        for key in ('mint', 'owner', 'delegate', 'closeAuthority', 'mintAuthority', 'freezeAuthority'):
            if key in info and info[key] is not None:
                address(info[key])
        for key in ('tokenAmount', 'rentExemptReserve', 'delegatedAmount'):
            if key in info:
                info[key] = token_amount(info[key])
        for key in ('isNative', 'isInitialized'):
            if key in info:
                require(type(info[key]) is bool, 'Invalid parsed token flag')
        if 'state' in info:
            require(info['state'] in ('initialized', 'uninitialized', 'frozen'), 'Invalid parsed token state')
        if 'decimals' in info:
            integer(info['decimals'])
        if 'supply' in info:
            require(isinstance(info['supply'], str) and info['supply'].isdigit(), 'Invalid mint supply')
    return result


def account_row(value, strip_metadata=False):
    result = select(value, {'pubkey', 'account'}, {'pubkey', 'account'})
    address(result['pubkey'])
    result['account'] = account(result['account'], strip_metadata)
    return result


def integer(value, nullable=False):
    require((nullable and value is None) or type(value) is int, 'Expected integer schema field')
    return value


def token_amount(value):
    result = select(value, {'amount', 'decimals', 'uiAmount', 'uiAmountString'}, {'amount', 'decimals'})
    require(isinstance(result['amount'], str) and result['amount'].isdigit(), 'Invalid raw token amount')
    integer(result['decimals'])
    require('uiAmount' not in result or result['uiAmount'] is None or
            isinstance(result['uiAmount'], (int, Decimal)), 'Invalid displayed amount')
    require('uiAmountString' not in result or isinstance(result['uiAmountString'], str), 'Invalid amount string')
    return result


def instruction(value, data_limits, resolved_program=None):
    result = select(value, {'programId', 'programIdIndex', 'accounts', 'stackHeight'})
    if 'programId' in result:
        address(result['programId'])
    if value.get('program') in {'system', 'spl-token', 'spl-token-2022'}:
        result['program'] = value['program']
    if 'accounts' in result:
        require(isinstance(result['accounts'], list), 'Expected instruction account array')
        for key in result['accounts']:
            address(key) if isinstance(key, str) else integer(key)
    for key in ('programIdIndex', 'stackHeight'):
        if key in result:
            integer(result[key], nullable=key == 'stackHeight')
    program = value.get('programId') or resolved_program
    if 'data' in value and program in data_limits:
        raw = decode58(value['data']) if value['data'] else b''
        limit = data_limits[program]
        if isinstance(limit, dict):
            limit = limit.get(raw[:8].hex(), limit['default'])
        result['data'] = encode58(raw if limit is None else raw[:limit]) if raw else ''
    parsed = value.get('parsed')
    if isinstance(parsed, dict):
        # Only native/token parsed semantics affect the historical selectors.
        if program in (
                '11111111111111111111111111111111',
                'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
                'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb') and parsed.get('type') in {
                    'transfer', 'transferWithSeed', 'createAccount', 'createAccountWithSeed',
                    'closeAccount', 'transferChecked'}:
            result['parsed'] = select(parsed, {'type', 'info'}, {'type', 'info'})
            result['parsed']['info'] = select(parsed['info'], {
                'source', 'destination', 'newAccount', 'lamports', 'owner', 'multisigOwner',
                'account', 'authority', 'multisigAuthority', 'mint', 'amount', 'tokenAmount',
            })
            for key, child in result['parsed']['info'].items():
                if key in {'lamports'}:
                    integer(child)
                elif key == 'amount':
                    require((isinstance(child, str) and child.isdigit()) or type(child) is int, 'Invalid transfer amount')
                elif key == 'tokenAmount':
                    result['parsed']['info'][key] = token_amount(child)
                else:
                    address(child)
    return result


def transaction(value, data_limits):
    if value is None:
        return None
    result = select(value, {'slot', 'blockTime', 'transactionIndex', 'version'}, {'slot'})
    tx = value['transaction']
    require(isinstance(tx, dict), 'Expected parsed transaction object')
    msg = select(tx['message'], {'accountKeys', 'header', 'recentBlockhash', 'addressTableLookups'},
                 {'accountKeys'})
    all_keys = [key['pubkey'] if isinstance(key, dict) else key for key in tx['message']['accountKeys']]
    loaded_keys = (value.get('meta') or {}).get('loadedAddresses') or {}
    all_keys += loaded_keys.get('writable', []) + loaded_keys.get('readonly', [])
    def project_instruction(row):
        index = row.get('programIdIndex')
        if index is not None:
            require(type(index) is int and 0 <= index < len(all_keys), 'Program index out of bounds')
        return instruction(row, data_limits, all_keys[index] if index is not None else None)
    msg['instructions'] = [project_instruction(row) for row in tx['message']['instructions']]
    msg['accountKeys'] = [select(key, {'pubkey', 'writable', 'signer', 'source'}, {'pubkey'})
                          if isinstance(key, dict) else key for key in msg['accountKeys']]
    if 'header' in msg:
        msg['header'] = strict(msg['header'], {'numRequiredSignatures', 'numReadonlySignedAccounts', 'numReadonlyUnsignedAccounts'})
        for item in msg['header'].values():
            integer(item)
    for key in msg['accountKeys']:
        address(key['pubkey'] if isinstance(key, dict) else key)
        if isinstance(key, dict):
            require(set(key) <= {'pubkey', 'writable', 'signer', 'source'}, 'Unknown account key field')
            require(all(type(key[field]) is bool for field in ('writable', 'signer') if field in key), 'Invalid signer flags')
            require(key.get('source') in (None, 'transaction', 'lookupTable'), 'Unknown account key source')
    if 'recentBlockhash' in msg:
        address(msg['recentBlockhash'])
    if 'addressTableLookups' in msg:
        msg['addressTableLookups'] = msg['addressTableLookups'] or []
        msg['addressTableLookups'] = [strict(row, {'accountKey', 'writableIndexes', 'readonlyIndexes'},
                                                  {'accountKey', 'writableIndexes', 'readonlyIndexes'})
                                    for row in msg['addressTableLookups']]
        for row in msg['addressTableLookups']:
            address(row['accountKey'])
            for key in ('writableIndexes', 'readonlyIndexes'):
                for index in row[key]:
                    integer(index)
    require(isinstance(tx['signatures'], list) and all(isinstance(s, str) and len(decode58(s)) == 64 for s in tx['signatures']), 'Invalid signature encoding')
    result['transaction'] = {'signatures': tx['signatures'], 'message': msg}
    meta = value.get('meta')
    if meta is None:
        result['meta'] = None
    else:
        result['meta'] = select(meta, {'fee', 'preBalances', 'postBalances',
                                      'computeUnitsConsumed', 'costUnits'})
        result['meta']['err'] = None if meta.get('err') is None else {'failed': True}
        for key in ('fee', 'computeUnitsConsumed', 'costUnits'):
            if key in result['meta']:
                integer(result['meta'][key], nullable=True)
        for key in ('preBalances', 'postBalances'):
            if key in result['meta'] and result['meta'][key] is not None:
                for child in result['meta'][key]:
                    integer(child)
        for key in ('preTokenBalances', 'postTokenBalances'):
            result['meta'][key] = []
            for row in meta.get(key) or []:
                projected = select(row, {'accountIndex', 'mint', 'owner', 'programId'}, {'accountIndex', 'mint'})
                integer(projected['accountIndex'])
                for field in ('mint', 'owner', 'programId'):
                    if field == 'owner' and projected.get(field) == chr(0):
                        # Preserve the exact historical NUL sentinel; it is not a
                        # Solana address and cannot identify a participant.
                        pass
                    elif field in projected and projected[field] is not None:
                        address(projected[field])
                    elif field in projected:
                        del projected[field]
                if 'uiTokenAmount' in row:
                    projected['uiTokenAmount'] = token_amount(row['uiTokenAmount'])
                result['meta'][key].append(projected)
        if meta.get('loadedAddresses') is not None:
            loaded = strict(meta['loadedAddresses'], {'writable', 'readonly'}, {'writable', 'readonly'})
            for rows in loaded.values():
                for key in rows:
                    address(key)
            result['meta']['loadedAddresses'] = loaded
        result['meta']['innerInstructions'] = [dict(index=row['index'],
                                                    instructions=[project_instruction(i) for i in row['instructions']])
                                                for row in meta.get('innerInstructions') or []]
        # logMessages and returnData are not membership facts and may carry arbitrary text.
    return result


def signature(value):
    result = select(value, {'signature', 'slot', 'blockTime', 'confirmationStatus',
                            'transactionIndex'}, {'signature', 'slot'})
    result['err'] = None if value.get('err') is None else {'failed': True}
    require(isinstance(result['signature'], str) and len(decode58(result['signature'])) == 64,
            'Invalid signature identifier')
    integer(result['slot'])
    for key in ('blockTime', 'transactionIndex'):
        if key in result:
            integer(result[key], nullable=True)
    require(result.get('confirmationStatus') in (None, 'processed', 'confirmed', 'finalized'),
            'Invalid confirmation status')
    return result


def das_item(value):
    result = select(value, {'id'}, {'id'})
    if 'ownership' in value:
        result['ownership'] = select(value['ownership'], {'owner', 'frozen', 'delegated', 'delegate',
                                                        'ownership_model'}, {'owner'})
    if 'token_info' in value and value['token_info'] is not None:
        result['token_info'] = select(value['token_info'], {'associated_token_address', 'decimals',
                                                          'supply', 'balance'})
    if 'mint_extensions' in value and value['mint_extensions'] is not None:
        result['mint_extensions'] = {}
        if 'token_group_member' in value['mint_extensions']:
            result['mint_extensions']['token_group_member'] = select(
                value['mint_extensions']['token_group_member'], {'mint', 'group', 'member_number'})
    return result


ACCOUNT_METHODS = {'getProgramAccounts', 'getProgramAccountsV2', 'getMultipleAccounts',
                   'getAccountInfo', 'getTokenAccountsByOwner'}
METHODS = ACCOUNT_METHODS | {'getTransactionsForAddress', 'getTransaction', 'getSignaturesForAddress',
                             'searchAssets', 'getAssetsByAuthority', 'getAssetsByOwner',
                             'getTokenAccounts', 'getAssetBatch',
                             'getTokenLargestAccounts', 'getTokenSupply', 'getBalance',
                             'getSlot', 'getBlockTime'}


def rpc_response(value, method, strip_metadata=False, instruction_data_limits=None):
    output = select(value, {'jsonrpc', 'id'})
    if 'error' in value:
        output['error'] = select(value['error'], {'code'}, {'code'})
        return output
    require('result' in value, 'Missing RPC result')
    result = value['result']
    if method in ACCOUNT_METHODS:
        if method == 'getAccountInfo':
            projected = {'context': context(result['context']), 'value': account(result['value'], strip_metadata)}
        elif method == 'getMultipleAccounts':
            projected = {'context': context(result['context']),
                         'value': [account(row, strip_metadata) for row in result['value']]}
        else:
            if isinstance(result, list):
                projected = [account_row(row, strip_metadata) for row in result]
            else:
                projected = select(result, {'paginationKey', 'paginationToken', 'totalResults', 'count'})
                if 'context' in result:
                    projected['context'] = context(result['context'])
                rows = result.get('value', result)
                if isinstance(rows, list):
                    projected['value'] = [account_row(row, strip_metadata) for row in rows]
                else:
                    target = select(rows, {'paginationKey', 'paginationToken', 'totalResults', 'count'})
                    target['accounts'] = [account_row(row, strip_metadata) for row in rows['accounts']]
                    if 'value' in result:
                        projected['value'] = target
                    else:
                        projected.update(target)
    elif method == 'getTransactionsForAddress':
        require(instruction_data_limits is not None, 'Transaction publication requires an explicit instruction schema')
        projected = select(result, {'paginationToken'}, {'data'})
        projected['data'] = [transaction(row, instruction_data_limits) if isinstance(row, dict) and 'transaction' in row else signature(row)
                             for row in result['data']]
    elif method == 'getTransaction':
        require(instruction_data_limits is not None, 'Transaction publication requires an explicit instruction schema')
        projected = transaction(result, instruction_data_limits)
    elif method == 'getSignaturesForAddress':
        projected = [signature(row) for row in result]
    elif method == 'getAssetBatch':
        projected = [das_item(row) if row is not None else None for row in result]
    elif method.startswith('getAssets') or method == 'searchAssets':
        projected = select(result, {'total', 'limit', 'page', 'cursor', 'last_indexed_slot'}, {'items'})
        projected['items'] = [das_item(row) for row in result['items']]
    elif method == 'getTokenAccounts':
        projected = select(result, {'total', 'limit', 'page', 'cursor', 'last_indexed_slot'})
        projected['token_accounts'] = [select(row, {'address', 'owner', 'mint', 'amount', 'decimals'},
                                             {'address', 'owner', 'mint', 'amount'}) for row in result['token_accounts']]
    elif method in {'getSlot', 'getBlockTime'}:
        require(type(result) is int or result is None, 'Expected integer RPC result')
        projected = result
    else:
        projected = {'context': context(result['context'])}
        if method == 'getTokenLargestAccounts':
            projected['value'] = [select(row, {'address', 'amount', 'decimals', 'uiAmount', 'uiAmountString'},
                                        {'address', 'amount'}) for row in result['value']]
        elif method == 'getTokenSupply':
            projected['value'] = select(result['value'], {'amount', 'decimals', 'uiAmount', 'uiAmountString'})
        else:
            projected['value'] = result['value']
    output['result'] = projected
    return output


def identity_rows(value):
    from .exclusions import SERVICE_CATEGORIES
    require(isinstance(value, list), 'Expected service classification array')
    result = []
    for row in value:
        projected = select(row, {'address', 'type', 'category'}, {'address'})
        address(projected['address'])
        require(projected.get('type') is None or isinstance(projected['type'], str), 'Invalid classification type')
        require(projected.get('category') is None or isinstance(projected['category'], str), 'Invalid service category')
        projected['type'] = 'unknown' if (projected.get('type') or 'unknown') == 'unknown' else 'classified'
        projected['category'] = projected.get('category') if projected.get('category') in SERVICE_CATEGORIES else None
        result.append(projected)
    return result
