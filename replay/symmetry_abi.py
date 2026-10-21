"""Read the selected published SDK ABI declarations without executing JavaScript."""
import re
from .core import require

SPECS = {
    'depositTokensIx': ('depositTokens', 'DEPOSIT_TOKENS_DISCRIMINATOR', 'owner', 'array10'),
    'mintVaultIx': ('mintVault', 'MINT_VAULT_DISCRIMINATOR', 'buyer', 'mint'),
    'redeemTokensIx': ('redeemTokens', 'REDEEM_TOKENS_DISCRIMINATOR', 'owner', 'redeem'),
}


def declarations(deposit, withdraw):
    output = []
    for function, (name, constant, beneficiary, check) in SPECS.items():
        source = withdraw if function == 'redeemTokensIx' else deposit
        constants = re.findall(r'const ' + constant + r' = Buffer.from\(\[([0-9, ]+)\]\);', source)
        require(len(constants) == 1, 'SDK discriminator declaration missing/repeated')
        discriminator = bytes(int(value.strip()) for value in constants[0].split(','))
        require(len(discriminator) == 8, 'SDK discriminator length differs')
        start = source.index('function ' + function + '(params) {')
        body = source[start:].split('\nfunction ', 1)[0]
        key_blocks = re.findall(r'const keys = \[([\s\S]*?)\n    \];', body)
        if function == 'depositTokensIx':
            key_blocks = re.findall(r'const keys = \[([\s\S]*?)\n        \];', body)
        require(len(key_blocks) == 1, 'SDK fixed account declaration missing/repeated')
        accounts = re.findall(r'\{ pubkey: (.*?), is(?:Signer|Writable):', key_blocks[0])
        require(accounts and len(accounts) == len(set(accounts)) and accounts.count(beneficiary) == 1,
                'SDK beneficiary/account declarations differ')
        rule = dict(name=name, position=accounts.index(beneficiary), kind='address', amount_check=check)
        if check == 'array10':
            require('while (amounts.length < 10)' in body and '.toArray("le", 8)' in body and
                    'Buffer.concat([discriminator, amountsBuffer])' in body, 'SDK deposit encoding differs')
        elif check == 'mint':
            require('data: MINT_VAULT_DISCRIMINATOR' in body and accounts.count('buyerVaultATA') == 1,
                    'SDK mint encoding differs')
            rule['destination_position'] = accounts.index('buyerVaultATA')
        else:
            require('const data = discriminator;' in body, 'SDK redeem encoding differs')
        output.append(dict(function=function, discriminator=discriminator.hex(), accounts=accounts, rule=rule))
    return output
