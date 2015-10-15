# PROTOCOL

## MESSAGE:
- begin header: 8 x 256 bytes
*  command block   (256 bytes -> RSA-2048, contents: 245 bytes)
  * 1 byte protocol version
  * 1 byte command (put = 1, relay = 2, ack = 4)
  * 32 byte symmetric key for transport container
  * 4 byte symmetric iv for transport container
  * 32 byte user hash (empty in case of relay)
  * case put/relay:  1 byte URL-length, 172 byte URL (utf-8 encoded)
*  payload


Node receives message
*  decrypt first command block (node's private RSA key)
  * check protocol version
  * decrypt remaining command blocks and payload 1 by 1 with contained AES parameters
  * handle command (relay-only nodes only process RELAY commands and drop everything else)
    * PUT:
      * read user hash
      * extract ACK payload
	  * generate package hash
      * store payload if it does not exist yet (goto RELAY)
      * replace message payload with ACK payload in transport container
    * RELAY:  read target address
    * ACK:    store ack message for client
  * shift command blocks left and pad right with random bytes
  * send to target node
