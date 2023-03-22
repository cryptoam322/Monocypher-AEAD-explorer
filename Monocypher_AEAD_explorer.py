"""
This program is a basic command line interface around the monocypher library(notably the lock/unlock functions).
This program is NOT SECURE for production uses.
To be frank, if you are thinking about using this for production, go download the library via pip install pymonocypher(or python -m pip install pymonocypher).
This program allows the user to pass base 64 encoded encrypted and additional data along with hexadecimal key and nonce(if none is given it will use a default one).

This program was made and uses pymonocypher version 3.1.3.1
You may encounter errors with other versions although that is unlikely.
If you do, check https://pypi.org/project/pymonocypher/ and https://monocypher.org/ for any updates/changes that may have caused problems.

Monocypher_AEAD_explorer - A cli interface intended to allow simple and quick exploration of monocypher lock() and unlock()
Copyright (C) 2023 cryptoam
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""
#This program is NOT INTENDED FOR PRODUCTION USE
#Please see above text for more info

import monocypher   #used for encryption, intended version is 3.1.3.1, you may find decryption failures and/or other errors with other versions
import base64           #used to encode output data in a manner that is safely handleable by a wide array of software
import cmd              #used to enable cli functionality
import string           #used to check hexadecimal validity
import typing           #used to help others reason about the code(expected input types)
from ast import literal_eval    #used to retrieve help text from help.txt
import secrets          #used for cryptographicaly secure random numbers in the generate command

#This program uses the monocypher module for it's secure encryption/decryption capability.
#This allows one to protect both encrypted data and unecrypted data(in this case from tampering)

#default values
default_data="No data"



def main():
    """Not much is held here specifically"""
    wrapper().cmdloop()
    exit()



class wrapper(cmd.Cmd):
    """This provides cli handling"""
    intro="This is Monocypher AEAD explorer ver.1\nThis program is under GPL v3 or later versions, see the associated LICENSE file for license details.\nGithub link is at https://github.com/cryptoam322/Monocypher-AEAD-explorer.\nUse command help if you are uncertain on how to procede."
    prompt=">"
    def do_encrypt(self,arg):
        """Starts encryption mode"""
        args=parse(arg)
        valid_args=[False]
        if len(args)==3:                        #refactor argument validation code here
            key, nonce, plaintext=args
            data=default_data
            valid_args=check_encrypt_parameters(key, nonce, plaintext, data)
        elif len(args)==4:
            key, nonce, plaintext, data=args
            valid_args=check_encrypt_parameters(key, nonce, plaintext, data)
        elif len(args)==0:
            valid_args=check_encrypt_parameters(None, None, None, None)
            print("This function is expecting either three or four arguments. See 'help encrypt' for more information.")
        elif len(args)==1:
            key=args[0]
            valid_args=check_encrypt_parameters(key, None, None, None)
            print("This function is expecting either three or four arguments. See 'help encrypt' for more information.")
        elif len(args)==2:
            key, nonce=args
            valid_args=check_encrypt_parameters(key, nonce, None, None)
            print("This function is expecting either three or four arguments. See 'help encrypt' for more information.")
        else:
            key, nonce, plaintext, data=args
            valid_args=check_encrypt_parameters(key, nonce, plaintext, data)
            print("This function is expecting either three or four arguments. See 'help encrypt' for more information.")
        if valid_args[0]==False:
            invalid_args=valid_args[1]
            if "key" in invalid_args:
                print("The key is invalid. See 'help encrypt' for more information.")
            else:
                pass
            if "nonce" in invalid_args:
                print("The nonce is invalid. See 'help encrypt' for more information.'")
            else:
                pass
            if "plaintext" in invalid_args:
                print("The plaintext is invalid. See 'help encrypt' for more information.'")
            else:
                pass
            if "associated data" in invalid_args:
                print("The associated data is invalid. See 'help encrypt' for more information.'")
        else:
            result=encrypt(key, nonce, plaintext, data)
            ciphertext, data, mac=result
            print("The ciphertext is\n"+ciphertext)
            input()
            print("The associated data is\n"+data)
            input()
            print("The mac is\n"+mac)
            input()
    def do_decrypt(self,arg):
        """Starts decryption mode"""
        args=parse(arg)
        valid_args=[False]
        key=None
        nonce=None
        ciphertext=None
        data=None
        mac=None
        if len(args)==5:
            key, nonce, ciphertext, data, mac=args
            valid_args=check_decrypt_parameters(key, nonce, ciphertext, data, mac)
        else:
            print("This argument is expecting five arguments. See 'help decrypt' for more information.")
        if valid_args[0]==False:
            try:
                invalid_args=valid_args[1]
                if "key" in invalid_args:
                    print("The key is invalid. See 'help decrypt' for more information.")
                else:
                    pass
                if "nonce" in invalid_args:
                    print("The nonce is invalid. See 'help decrypt' for more information.")
                else:
                    pass
                if "ciphertext" in invalid_args:
                    print("The ciphertext is invalid. See 'help decrypt' for more information.")
                else:
                    pass
                if "data" in invalid_args:
                    print("The associated data is invalid. See 'help decrypt' for more information.")
                else:
                    pass
                if "mac" in invalid_args:
                    print("The mac is invalid. See 'help decrypt' for more information.")
                else:
                    pass
            except: #this means that the amount of arguments is not 5 and therefore the appropiate text(need 5 arguments specifically) has already been displayed
                pass  #PS, refactor this as well
        else:
            result=decrypt(key, nonce, ciphertext, data, mac)
            if result==None:
                print("Authentication failed, unable to decrypt.")
            else:
                print("Authentication passed, decryption sucessful.")
                plaintext, data=result
                print("The plaintext is\n"+plaintext)
                input()
                print("The associated data is\n"+data)
                input()
    def do_license(self, arg):
        """Displays license information"""
        args=parse(arg)
        if args!=():
            print("This function does not take any arguments")
        else:
            print("""Monocypher_explorer - intended to allow simple and quick exploration of monocypher lock() and unlock()
Copyright (C) 2023 cryptoam
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.""")
            input("Full license follows: ")
            try:
                with open("LICENSE.txt","r") as License:
                    license=License.read()
                    print(license)
            except:
                print("Unable to access LICENSE.txt")
                print("Check to see if you have recieved the license. Full original source code is at https://github.com/cryptoam322/Monocypher-AEAD-explorer.")
                print("See https://www.gnu.org/licenses/gpl-3.0.txt for the license, archived copy at https://web.archive.org/web/20230000000000*/https://www.gnu.org/licenses/gpl-3.0.txt")
    def do_help(self, arg):
        """Displays either basic help text or a longer more specific help depending on arguement"""
        args=parse(arg)
        if len(args)==0:
            line=get_help("starting help")
            print(line)
        elif len(args)==1:
            argument=args[0]
            if argument=="encrypt":
                line=get_help("encrypt")
                print(line)
            elif argument=="decrypt":
                line=get_help("decrypt")
                print(line)
            elif argument=="help":
                line=get_help("help")
                print(line)
            elif argument=="about":
                line=get_help("about")
                print(line)
            elif argument=="license":
                line=get_help("license")
                print(line)
            elif argument=="generate":
                line=get_help("generate")
                print(line)
            elif argument=="exit":
                line=get_help("exit")
                print(line)
            else:
                line=get_help("invalid help arg")
                print(line)
        else:
            line=get_help("too many args")
            print(line)
    def do_about(self, arg):
        """Displays text about why this program exists"""
        args=parse(arg)
        if args!=():
            print("This function does not take any arguments")
        else:
            print("""
        This program is intended to be used as an exploration of AEAD(authenticated encryption with associated data).
        This program can also be used to quickly encrypt and decrypt data in a manner that is compatible with Monocypher(and libsodium(NOT Tweet(NaCI) as per documentation)).
        This program assumes all data(plaintext or associated) is utf-8 encoded.

        You are invited to help out by forking this and/or submitting bug reports.
        Security issues that do not involve insecure key/nonces generation or insecure handling of sensitive data should be reported to cryptoam(aT)gmail(D0t)com or on the github.
        """)
    def do_generate(self, arg):
        """Used to help generate cryptoparameters like keys and nonce """
        args=parse(arg)
        valid_args=False
        if len(args)==2:
            mode, generate_type=args
            if mode not in("pad", "random"):
                valid_args=False
            else:
                if generate_type not in("key", "nonce"):
                    valid_args=False
                else:
                    valid_args=True
                    data=None
        elif len(args)==3:
            mode, generate_type, data=args
            if mode not in("pad", "random"):
                valid_args=False
            else:
                if generate_type not in("key", "nonce"):
                    valid_args=False
                else:
                    if is_hex(data)==False:
                        valid_args=False
                    else:
                        valid_args=True
        else:
            print("This command expects two to three arguments. See 'help generate' for more information.")
        if valid_args==True:
            if data==None:  #no data provided, we must generate the entirety of the key/nonce itself
                if mode=="pad" and generate_type=="key":
                    result=""
                    for i in range(0,64):
                        result=result+"0"
                    print("Your generated key is: "+result)
                elif mode=="pad" and generate_type=="nonce":
                    result=""
                    for i in range(0,48):
                        result=result+"0"
                    print("Your generated nonce is: "+result)
                elif mode=="random" and generate_type=="key":
                    result=secrets.token_hex(32)
                    print("Your generated key is: "+result)
                elif mode=="random" and generate_type=="nonce":
                    result=secrets.token_hex(24)
                    print("Your generated nonce is: "+result)
            else:               #data is provided
                if len(data)>=64 and generate_type=="key":          #this and the below case is when we have at least enough data to directly use to generate the key
                    result=data[0:64]
                    print("Your generated key is: "+result)
                elif len(data)>=48 and generate_type=="nonce":  #the other case as mentioned above but for the nonce
                    result=data[0:48]
                    print("Your generated nonce is: "+result)
                elif len(data)<64 and generate_type=="key":         #we do not have enough data to generate the key
                    remaining_length=64-len(data)
                    if mode=="pad":
                        remainder=""
                        for i in range(0,remaining_length):
                            remainder=remainder+"0"
                    else:
                        if remaining_length%2==1:   #secrets.token_hex() only gives bytes in hex (eg 2 digits), we'll need to do some trimming for the odd amount of remaining digits
                            remainder=secrets.token_hex(int((remaining_length+1)/2))    #generate excess hexadecimal digits
                            remainder=remainder[0:len(remainder)-1]                             #trim said excess
                        else:
                            remainder=secrets.token_hex(int(remaining_length/2))
                    result=data+remainder
                    print("Your generated key is: "+result)
                elif len(data)<48 and generate_type=="nonce":       #we do not have enough data to generate the nonce
                    remaining_length=48-len(data)
                    if mode=="pad":
                        remainder=""
                        for i in range(0,remaining_length):
                            remainder=remainder+"0"
                    else:
                        if remaining_length%2==1:   #secrets.token_hex() only gives bytes in hex (eg 2 digits), , we'll need to do some trimming for the odd amount of remaining digits
                            remainder=secrets.token_hex(int((remaining_length+1)/2))    #generate excess
                            remainder=remainder[0:len(remainder)-1]                             #trim said excess
                        else:
                            remainder=secrets.token_hex(int(remaining_length/2))
                    result=data+remainder
                    print("Your generated nonce is: "+result)
                else:
                    print("Something has gone wrong with generating the cryptoparameter. Somehow an invalid combination of arguements has occured here")
        else:
            print("The provided arguments are invalid. See 'help generate' for more information.")
    def do_exit(self, arg):
        """Used to terminate the cmdloop and exit this program"""
        args=parse(arg)
        if args!=():
            print("This function does not take any arguments")
        else:
            return True



def parse(arg:str):
    """A simple function that saves me the pain of copy pasting this snippet everywhere"""
    return tuple(arg.split())



def is_hex(test_string:str):
    """Another snippet of code. This one makes sure that there are only hexadecimal characters(no 0x allowed) in the string"""
    return all(c in string.hexdigits for c in test_string)



def check_encrypt_parameters(key:str, nonce:str, plaintext:str, data:str):
    """This function makes sure that input arguments for the needed parameters are valid"""
    valid_param=True
    invalid_params=[]
    if key==None:
        valid_param=False
        invalid_params.append("key")
    else:
        if is_hex(key) and len(key)==64:
            pass
        else:
            valid_param=False
            invalid_params.append("key")
    if nonce==None:
        valid_param=False
        invalid_params.append("nonce")
    else:
        if is_hex(nonce) and len(nonce)==48:
            pass
        else:
            valid_param=False
            invalid_params.append("nonce")
    if plaintext!=None:     #turns out we do need to check plaintext and associated data
        pass
    else:
        valid_param=False
        invalid_params.append("plaintext")
    if data!=None:
        pass
    else:
        valid_param=False
        invalid_params.append("associated data")
    return(valid_param,invalid_params)



def encrypt(key:str, nonce:str, plaintext:str, data:str):
    """This function handles conversion of the string inputs into a form that monocypher can handle, applies lock(), and then returns ready to use string outputs"""
    key=bytes.fromhex(key)              #convert the hexadecimal into bytes
    nonce=bytes.fromhex(nonce)
    plaintext=bytes(plaintext, "utf-8") #convert the arbitary strings into bytes
    data=bytes(data, "utf-8")
    result=monocypher.lock(key,nonce,plaintext,data) #perform the operation
    mac, ciphertext=result
    ciphertext=base64.b64encode(ciphertext)     #convert into base 64 for an easier time handling as strings(copy+paste)
    data=base64.b64encode(data)
    mac=base64.b64encode(mac)
    ciphertext=ciphertext.decode("utf-8")
    data=data.decode("utf-8")
    mac=mac.decode("utf-8")
    return(ciphertext, data, mac)


    
def check_decrypt_parameters(key:str, nonce:str, ciphertext:str, data:str, mac:str):
    """
    This function checks that input arguments for decryption are valid
    """
    valid_param=True
    invalid_params=[]
    if is_hex(key) and len(key)==64:
        pass
    else:
        valid_param=False
        invalid_params.append("key")
    if is_hex(nonce) and len(nonce)==48:
        pass
    else:
        valid_param=False
        invalid_params.append("nonce")
    try:
        base64.b64decode(ciphertext, validate=True)
    except base64.binascii.Error as e:
        valid_param=False
        invalid_params.append("ciphertext")
    try:
        base64.b64decode(data, validate=True)
    except base64.binascii.Error as e:
        valid_param=False
        invalid_params.append("data")
    try:
        a=base64.b64decode(mac, validate=True)
        if len(a)!=16:  #mac must be 16 bytes
            valid_param=False
            invalid_params.append("mac")
    except base64.binascii.Error as e:
        valid_param=False
        invalid_params.append("mac")
    return(valid_param,invalid_params)



def decrypt(key:str, nonce:str, ciphertext:str, data:str, mac:str):
    key=bytes.fromhex(key)
    nonce=bytes.fromhex(nonce)
    ciphertext=base64.b64decode(ciphertext)
    data=base64.b64decode(data)
    mac=base64.b64decode(mac)
    result=monocypher.unlock(key, nonce, mac, ciphertext, data)
    if result==None:    #Authentication failure, see monocypher documentation
        return(None)    #AKA we will refuse to decrypt possibly tampered data(or there is an incorrect key/nonce combination which would fail anyways)
    else:
        plaintext=result.decode("utf-8")
        data=data.decode("utf-8")
        return(plaintext,data)



def get_help(line_id):
    """This function grabs the relevant help text from help.txt"""
    try:
        with open("help.txt","r") as help_file:
            try:
                help_line_dict=literal_eval(help_file.read())
            except:
                return("Something has gone wrong with attempting to read the help file's contents. It may have been corrupted.")
            try:
                line=help_line_dict[line_id]
                return(line)
            except KeyError as e:
                return("The appropiate help text could not be found. It may be corrupted or the relevant line is not available.")
            except:
                return("Something has gone wrong with attempting to look up the relevant help text id.")
    except:
        return("Something has gone wrong with trying to access the help file. The file may be misplaced, deleted, or misnamed.")



if __name__=="__main__":
    """Boilerplate code"""
    main()