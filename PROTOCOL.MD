# PROTOCOL

## Crypto parameters
- Asymmetric encryption:
	- RSA-2048 (256 bytes message size / 245 bytes content size)
	- padding scheme: pkcs1_oaep
- Symmetric encryption:
	- AES-256-cbc (no auto padding, padding is done by generating appropriate random bytes)
	- 32-bit key size
	- 16-bit IV

## MESSAGE:
* header: 8 x 256 bytes
  * command block   (asymmetrically encrypted)
    * 1 byte protocol version
    * 1 byte command (put = 1, relay = 2, ack = 4)
    * 32 byte symmetric key for command block and payload layers
    * 4 byte symmetric IV for command block and payload layers
    * 32 byte user hash (empty in case of relay)
    * case put/relay:  1 byte URL-length, 172 byte URL (utf-8 encoded)
* message body

## MESSAGE BODY
* header: 256 bytes (asymmetricaly encrypted with recipient's public key)
  * 32 byte symmetric  key for signed payload
  * 4 byte symmetric IV for signed payload
  * 4 byte payload length
* signed payload: payload length + 256 bytes (symmetrically encrypted with given parameters)
  * SHA-256 data hash: 256 bytes (asymmetrically encrypted with sender's private key)
  * payload

Node receives message
*  decrypt first command block (node's private RSA key)
  * check protocol version
  * decrypt remaining command blocks and payload 1 by 1 with contained AES parameters
  * handle command (relay-only nodes only process RELAY commands and drop everything else)
    * PUT:
      * read user hash
      * extract ACK message body
	  * generate message body hash
      * store remaining message body if it does not exist yet (goto RELAY)
      * replace message body with ACK message body
    * RELAY:
      * read target address
      * shift command blocks left and pad right with random bytes
      * send to target node
    * ACK:    store ack message for client
