import string

ciphertext_example = '''ad924af7a9cdaf3a1bb0c3fe1a20a3f367d82b0f05f8e75643ba688ea2ce8ec88f4762fbe93b50bf5138c7b699
a59a0eaeb4d1fc325ab797b31425e6bc66d36e5b18efe8060cb32edeaad68180db4979ede43856a24c7d
a59a0eaeaad7fc3c56fe82fd1f6bb5a769c43a0f0cfae74f0df56fdae3db8d9d840875ecae2557bf563fcea2
a59a0eaea8ddf93c08fe81e11e2ab2bb6d962f0f1af2f44243b46cc1b6d6c291995d65a9a5234aa204
ad924af7a9cdaf3a1bb0c3f51439a5b628cf215a1fbdee4302a77a8ea2cc86c8984d65ffac6c58bf5b71dab8841136
b09b4afda3caf93c5aa78ce6096bb2a67ad86e4302f3e10602b37acbb1829680935137e8bb2919b6503fccfdca5461
a59a0eaeb5d7af3115b287b31425e6a460d3200f19f5e35406f567dde3cc8d9c9e4179eee92557f1463edc
a18c09ebb6ccaf2d12bbc3c41227aaf37fde274c05bdf5471aa62edaac82968093452da9eb0456bd5b71c6bfcb56

ad924af7a9cdaf3a1bb0c3e71a27adf37fdf3a474dfef44914b17d8ea2cc86c89d4d72f9e93556a44d71dfb8980034b3cea5c4d4
ab864af9a7d4e4790db797fb5b00afbd6fc5acaff9f3e95443b961dda6829680930874e6a42156bf1f25c6a4891c6d
ad924ae0a3d1fb311facc3f5142eb5f366d93c0f01f2f04f0db22ec8b1cb8786925b37eaa82219b94a23ddf1931b34fa
ad924aefaad4af341fb0c3f0143ea8a728c1275b05bdff4916f92eccb6d6c286994672a9bd2356f15224cab9d1
ad924af7a9cdaf3a1bb0c3f51227aaf37cde2b0f18f3e04911b267d8aacc85c89b4179fcbd29
b39d1ee6e6cbe6210ea7c3e01e28a9bd6cc5690f1af2f4520bf561c8e3c68b9b824979eaac6c4ba4517d89f1ca
bd9b1ffcb598e62a5aaa8bf65b0ea7a17cde6e4e03f9a64315b07cd7b7ca8b86910863e1a8381ea21f38c7f183006df6c2a5
a59a0e6c462cf83113bd8bb31238e6be67c42bcded09ff4916f262c2e3c087c897085ae8a76019bc4671dabe8455
'''

def bytes_xor(bts1, bts2):
    return bytes([x ^ y for x, y in zip(bts1, bts2)])


lines = ciphertext_example.split()
xored_bts = bytes_xor(
    bytes.fromhex(lines[0]), 
    bytes.fromhex(lines[1])
    )
crib = 'and'
crib_bts = bytes(crib, encoding='ascii')

def yes_no(msg):
    resp = input(msg + ' (y/n): ')
    if resp == 'y':
        return True
    return False

def is_promising(text):
    promising_charset = string.ascii_letters + ' ,!?'
    for char in text:
        if char not in promising_charset:
            return False
    return True

def print_crib_result(xored_bts, crib_bts):
    for i in range(len(xored_bts) - len(crib_bts) + 1):
        try:
            result = bytes_xor(xored_bts[i:i+len(crib_bts)], crib_bts).decode('ascii')
            label = '[*]' if is_promising(result) else '[ ]'
        except UnicodeDecodeError:
            label = '[-]'
            result = ''

        print('{:2}{} {}'.format(i, label, result))


def print_common_cribs():
    crib_words = (
        'the', 'and', 'that', 'have',
        'for', 'not', 'with', 'you', 
        'this', 'from', 'they', 'say',
        'her', 'she', 'will',
        )
    for i, crib in enumerate(crib_words):
        crib_bts = bytes(crib, encoding='ascii')



# # get ciphertexts
# use_sample = yes_no('Do you want to use sample ciphertext messages?')
# if use_sample:
#     lines = ciphertext_example.split()
#     cipher1 = lines[0]
#     cipher2 = lines[1]
# else:
#     cipher1 = input('Enter first ciphertext:\n\t')
#     cipher2 = input('Enter second ciphertext:\n\t')

# # decode from hex
# cipher1_bts = bytes.fromhex(cipher1)
# cipher2_bts = bytes.fromhex(cipher2)

# check_common_crib = yes_no(f'Do you want to check common crib words?')
# if check_common_crib:
#     print_common_cribs()