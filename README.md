##Monocypher AEAD Explorer

If you want to make an translation and have the necessary files /changes necessary please send a pull request.


Monocypher AEAD Explorer
==================

A cli interface intended to allow simple and quick exploration of monocypher lock() and unlock()

**Warning: This program is not designed to and is not intended to provide security for production or sensitive systems. While it does use monocypher for the actual cryptographic code, this program does not provide protection in regards to details such as secure key generation or nonce selection.**

This python program is intended as a quick way to play around and use monocypher's implementation of AEAD. It consumes hexadecimal format key and nonce and utf-8 encoded plaintext and associated data and outputs base 64 encoded ciphertext, associated data, and message authentication code in encryption and the converse during decryption. It also comes with a simplistic but insecure(in the sense that it is easy to generate an all zero or otherwise insecure key/nonce) key/nonce generator.

##Getting started

To get started, download the repository and python(if it is not already on your system).
Then use `pip install -r requirements.txt` to download the needed module(pymonocypher).
Afterwards, run the program. Use `help` to learn the commands.

##Encryption

To encrypt a utf-8 string, use `encrypt key nonce plaintext associated_data`.
Both the key and nonce must be a hexadecimal string(64 and 48 digits respectively).
Plaintext is the utf-8 string that you want to encrypt.
Associated data is the utf-8 string that you do not want to encrypt but want to protect from alteration/tampering. You may not provide it in which case the program will default to using "No data" as the associated data.
The command will return a base 64 encoded ciphertext(the encrypted form of the plaintext), associated data, and a message authentication code(mac).
You will need the key, nonce, ciphertext, associated data, and message authentication code to successfully decrypt the ciphertext.

##Decryption

To decrypt, use `decrypt key nonce ciphertext associated_data mac`.
Both the key and nonce must be the same hexadecimal string used during encryption.
The ciphertext, associated data, and mac must be the generated base 64 encoded string generated earlier during encryption.
All of the above must be provided or else decryption will fail.
If authentication of the provided data is successful, the program will then provide the utf-8 encoded plaintext(having decrypted the provided ciphertext) and associated data.
If authentication is unsuccessful, the program will inform you as such and fail to provide any decoded utf-8 plaintext or associated data.
If you encounter an authentication failure, ensure that you have provided the right key/nonce pair and the correct base 64 encoded ciphertext, associated data, and mac group.

##Generating keys/nonces

**Warning: The way that this program implements this functionality makes it easy to generate weak keys/nonces. There are no security garuntees as to the safety of generated keys/nonces using this method.**

To generate a key or nonce in this program, use `generate mode type data`.
Mode must be either "pad" or "random".
Type must be either "key" or "nonce".
Data is an optional argument and must be hexadecimal if provided.
When mode is "pad" the program will add zeros to pad out the provided data to the needed length if insufficient or no data is given. This is obviously insecure and in the extreme case can lead to an all zero key/nonce.
When mode is "random" the program will use python's secrets module to generate random hexadecimal digits to pad the provided data to the needed length. This is in theory less insecure as the secrets library is used to collect cryptographically secure hexadecimal digits but it does not preclude the potential for a weak/predictable key or nonce from being generated(eg. you provide insecure/predictable data that is close to the needed size and only a small amount of random hexadecimal is needed to pad the key/nonce).
One can use random as the mode and not provide any data in order to directly use secrets.token_hex(). This should be secure but no guarantees are made in this regard.
The type argument is used to dictate the size of the output and therefore whether it can be used as a key or nonce.

##Bugs or Requested Changes

If there are bugs please send a pull request detailing what the bug is and how to replicate it.
If you have a change that you would like to make, please send a pull request. Keep in mind that the developer does not have much time for maintenance and this repository is only focused around using monocypher's lock() and unlock(). There will be no support for additional capabilities in monocypher and you are advised to fork this project if you wish for such.

##Security

If you find a security issue, please do not send a public pull request. Instead, contact me at cryptoam(At)gmail(D0t)com with the necessary information regarding the problem and potential fixes.
Keep in mind that this program is not intended to handle/generate key/nonce(and plaintext) material safely and any issues in that regard will likely not be fixed.
If a valid security issue is found, I will publish an advisory over at the github repository.