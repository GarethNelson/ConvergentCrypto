import Crypto
from Crypto import Random
from Crypto.Cipher import AES
from binascii import hexlify,unhexlify
import hashlib

prng = Random.new()

blocks = {}

user_blocks={}

def store_block(data,username,user_privkey,user_blockid):
    """ Stores an encrypted block if it's not already been stored
        Updates the user's profile with a list of blocks they own
         Params:
           data         - the data to be stored, the actual block in plaintext
           username     - duh
           user_privkey - arbitrary text string to generate a key from
           user_blockid - a string the user will use to identify this block
    """
    block_hash     = hashlib.sha256(data).hexdigest()
    converged_hash = hashlib.sha256(block_hash).hexdigest()
    
    if not blocks.has_key(converged_hash):
       converged_iv           = hashlib.sha512(block_hash).digest()[0:16]
       converged_key          = unhexlify(block_hash)
       crypter                = AES.new(converged_key, AES.MODE_CFB, converged_iv)
       blocks[converged_hash] = hexlify(data)

    if not user_blocks.has_key(username):
       user_blocks[username] = {}
    
    user_iv      = prng.read(16)
    user_key     = hashlib.sha256(user_privkey).digest()
    user_crypter = AES.new(user_key, AES.MODE_CFB, user_iv)

    user_blockdata = (user_iv,user_crypter.encrypt(block_hash))
    
    user_blocks[user_blockid] = user_blockdata

def retrieve_block(username,user_privkey,user_blockid):
    user_blockdata = user_blocks[user_blockid]
    user_iv        = user_blockdata[0]
    user_key       = hashlib.sha256(user_privkey).digest()
    user_crypter   = AES.new(user_key, AES.MODE_CFB, user_iv)
    block_hash     = user_crypter.decrypt(user_blockdata[1])
    converged_hash = hashlib.sha256(block_hash).hexdigest()
    converged_key  = unhexlify(block_hash)
    converged_iv   = hashlib.sha512(block_hash).digest()[0:16]
    data_crypter   = AES.new(converged_key, AES.MODE_CFB, converged_iv)
    return data_crypter.decrypt(blocks[converged_hash])

if __name__=='__main__':
   print 'Storing a random block in Alice\'s account, her key is SuperSecret1 and she uses RANDOM1 as her block ID'
   random_block = prng.read(2048)
   store_block(random_block,'alice','SuperSecret1','RANDOM1')
   
   print 'Storing the same random block in Bob\'s account, his key is IHaveAPassword and he uses LOLRANDOM as his block ID'
   store_block(random_block,'bob','IHaveAPassword','LOLRANDOM')
   
   print 'Dumping block keys, there should be only one:'
   print blocks.keys()
   
   print 'Retrieving block for Alice'
   alice_block = retrieve_block('alice','SuperSecret1','RANDOM1')

   print 'Retrieving block for Bob'
   bob_block = retrieve_block('bob','IHaveAPassword','LOLRANDOM')
   
   print 'Do they match?'
   print str(hexlify(alice_block)==hexlify(bob_block))


