#!/usr/bin/env python
"""
AndroidLockCracker - Cracking and generating Android lock hashes
Copyright (C) 2014  George Nicolaou (george({at})silensec({dot})com)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
from itertools import product
import string, getopt, sys, hashlib, struct, time

SHA1_LEN = 40
MD5_LEN = 32

class PasswordGestureGenerate(object):
    def __init__(self, sizeX=3, sizeY=3, gesture=None):
        self.sizeX = sizeX
        self.sizeY = sizeY
        self.gesture = gesture
        return
    
    def point_to_coords(self, point, sizeX=3, sizeY=3):
        column = (point % sizeY) - 1
        row = ( point - column * sizeX ) - 1
        yield ( column, row )
        
    def generate_gesture_string(self, gesture ):
        string = ""
        for point in gesture:
            string += chr(point)
        return string
    
    def generate_self_hash(self):
        if self.gesture == None:
            print "Bad gesture string"
            return False
        return self.generate_hash(self.generate_gesture_string(self.gesture))
    
    def generate_hash(self, gesture_string):
        return hashlib.sha1(gesture_string).hexdigest().upper()
    
class PasswordPinGenerate(object):
    def __init__(self, passwd=None, salt=None):
        self.passwd = passwd
        self.salt = salt
        if self.passwd != None and self.salt != None:
            self.salted = self.passwd + self.salt
        else:
            self.salted = None
        return
    
    def set_salt(self, salt=None):
        if salt == None:
            print "Bad salt"
            return False
        self.salt = salt
        return True
    
    def generate_self_hash_sha1(self):
        if self.salted == None:
            self.salted = self.passwd + self.salt
        return hashlib.sha1(self.salted).hexdigest()
    
    def generate_hash_sha1(self, passwd):
        salted = passwd + self.salt
        return hashlib.sha1(salted).hexdigest()
    
    def generate_self_hash(self):
        salted = self.passwd + self.salt
        return (hashlib.sha1(salted).hexdigest() + 
                hashlib.md5(salted).hexdigest()).upper()
    
    def generate_hash(self, passwd):
        salted = passwd + self.salt
        return (hashlib.sha1(salted).hexdigest() + 
                hashlib.md5(salted).hexdigest()).upper()

class PasswordPinCracker(object):
    def __init__(self, phash, salt, plengthbegin=4, plengthend=4, numeric=True, 
                 alpha=False, symbols=False):
        self.phash = phash.upper()
        self.phash_sha1 = phash[:SHA1_LEN]
        self.phash_md5 = phash[SHA1_LEN:]
        self.salt = salt
        self.plengthbegin = plengthbegin
        self.plengthend = plengthend
        self.numeric = numeric
        self.alpha = alpha
        self.symbols = symbols
        return
    
    def _gen_charlist(self):
        charlist = ""
        if self.numeric == True:
            charlist += string.digits
        if self.alpha == True:
            charlist += string.ascii_letters
        if self.symbols == True:
            charlist += '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ '
        return [_ for _ in charlist]
    
    def begin_wordlist_crack(self, wordlist):
        try:
            wordlist = [l.strip() for l in open(wordlist)]
        except:
            print "Bad wordlist file"
            return False
            
        generator = PasswordPinGenerate()
        generator.set_salt(self.salt)
        for passwd in wordlist:
            phash_sha1 = generator.generate_hash_sha1(passwd)
            if self.phash_sha1 == phash_sha1:
                phash = generator.generate_hash(passwd)
                if self.phash == phash:
                    return passwd
        return False
    
    def begin_brute_crack(self):
        generator = PasswordPinGenerate()
        generator.set_salt(self.salt)
        charlist = self._gen_charlist()
        for length in xrange(self.plengthbegin, self.plengthend+1):
            for passwd in product(charlist, repeat=length):
                passwd = ''.join(passwd)
                phash = generator.generate_hash(passwd)
                if self.phash == phash:
                    return passwd
        return False

class PasswordGestureCracker(object):
    def __init__(self, phash, sizeX=3, sizeY=3, lengthbegin=4, lengthend=4):
        self.phash = phash.upper()
        self.sizeX = sizeX
        self.sizeY = sizeY
        self.lengthbegin = lengthbegin
        self.lengthend = lengthend
        return
    
    def _gen_points(self):
        return [ _ for _ in range(self.sizeX*self.sizeY)]
    
    def begin_brute_crack(self):
        generator = PasswordGestureGenerate(self.sizeX, self.sizeY)
        gridpoints = self._gen_points()
        for length in xrange( self.lengthbegin, self.lengthend+1):
            #XXX Replace product() with something that doesn't generate 
            #repetitions (eg 1,1,...)
            for passwd in product(gridpoints, repeat=length):
                phash = generator.generate_hash(generator.generate_gesture_string(passwd))
                if phash == self.phash:
                    return passwd
        return False
        
def usage():
    options = [
        {"title": "Global Options:"},
        {"short": "-h", "long": "--help", "descr": "This help text"},
        {"short": "-s", "long": "--salt=", "descr": "The password salt (in decimal)"},
        {"title": "Cracking options:"},
        {"short": "-l", "long": "--length=", "descr": "The password fixed length"},
        {"short": "-B", "long": "--lengthbegin=", "descr": "The password begin length"},
        {"short": "-E", "long": "--lengthend=", "descr": "The password end length"},
        {"title": "PIN Cracking/Generation:"},
        {"short": "-w", "long": "--wordlist", "descr": "Use password wordlist"},
        {"short": "-a", "long": "--alpha", "descr": "Include letters in password generation/cracking"},
        {"short": "-n", "long": "--numeric", "descr": "Include numbers in password generation/cracking"},
        {"short": "-b", "long": "--symbols", "descr": "Include symbols in password generation/cracking"},
        {"title": "Gesture Cracking/Generation:"},
        {"short": "-g", "long": "--gridsize", "descr": "Grid square size eg: -g 3 (for 3x3)"},
    ]
    print "%s %s %s" % ( sys.argv[0], "[OPTION(S)]", "TYPE LOCK PASSWORD/HASH [SALT]" )
    print "Author: George Nicolaou, Silensec"
    print "TYPE - The type of processing to do:\n\tcrack - For cracking\n\tgenerate - For generating hashes"
    print "LOCK - The device lock type:\n\tpin - For PIN/Password locks (requires salt)\n\tgesture - For Gesture locks"
    print "PASSWORD/HASH - The password to generate hash for or the hash to crack password for.\n\t\t(Note: dump gesture hash using `hashdump -C gesture.key`)"
    print "SALT - The password salt to generate password with or the salt to crack password with (in decimal)\n"
    for opt in options:
        if "title" in opt:
            print opt["title"]
        else:
            print "\t%s %s\t%s" % (opt["short"], opt["long"], opt["descr"])
    print "Note: Default settings include only numeric PIN cracking"
    sys.exit()

class Options(object):
    PIN = 1
    GESTURE = 2
    salt = None
    passwd = None
    lock = None
    passwd_length = None
    passwd_length_begin = 4
    passwd_length_end = 16
    wordlist = None
    alpha = False
    numeric = True
    symbols = False
    gridX = 3
    gridY = 3

def handle_generate(opts):
    if opts.lock == opts.PIN:
        generator = PasswordPinGenerate(opts.passwd, opts.salt)
        phash = generator.generate_self_hash()
        print "Password Hash: %s\nPassword Salt: %s" % (phash, opts.strsalt)
        sys.exit()
    elif opts.lock == opts.GESTURE:
        gesture = [int(n)-1 for n in opts.passwd.split(",")]
        generator = PasswordGestureGenerate( opts.gridX, opts.gridY, gesture )
        print "Gesture Hash: %s\nGesture: %s" % (generator.generate_self_hash(), 
                                                 opts.passwd)
    return

def handle_crack(opts):
    if opts.lock == opts.PIN:
        if opts.passwd_length != None:
            opts.passwd_length_begin = opts.passwd_length
            opts.passwd_length_end = opts.passwd_length
        if opts.salt == None:
            print "No salt specified"
            return
        cracker = PasswordPinCracker( opts.passwd, opts.salt, 
                                      opts.passwd_length_begin, 
                                      opts.passwd_length_end, opts.numeric, 
                                      opts.alpha, opts.symbols )
        print "Cracking... (this might take a while)"
        if opts.wordlist != None:
            start = time.time()
            passwd = cracker.begin_wordlist_crack(opts.wordlist)
            took = time.time() - start
        else:
            start = time.time()
            passwd = cracker.begin_brute_crack()
            took = time.time() - start
    elif opts.lock == opts.GESTURE:
        if opts.passwd_length != None:
            opts.passwd_length_begin = opts.passwd_length
            opts.passwd_length_end = opts.passwd_length
        cracker = PasswordGestureCracker( opts.passwd, opts.gridX, opts.gridY, 
                                          opts.passwd_length_begin, 
                                          opts.passwd_length_end )
        
        print "Cracking... (this might take a while)"
        start = time.time()
        passwd = cracker.begin_brute_crack()
        took = time.time() - start
        if passwd != False:
            passwd = ','.join([str(x+1) for x in passwd])
    if passwd == False:
        print "Not found - Processing time: %.4f seconds" % took
    else:
        print "Processing time: %.4f seconds\nPassword: %s" % ( took, passwd )
    return

def main():
    if len(sys.argv) < 2:
        usage()
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hs:l:B:E:w:anbg:", 
            ["help","salt=","length=", "lengthbegin=", "lengthend=", 
             "wordlist=", "alpha", "numeric","symbols","gridsize="])
    except:
        usage()
    
    if len(args) < 3:
        usage()
    options = Options()

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            usage()
        elif opt in ('-s', '--salt'):
            options.salt = struct.pack('>q', long(arg)).encode("hex")
            options.strsalt = arg
        elif opt in ('-l', '--length'):
            options.passwd_length = int(arg)
        elif opt in ('-B', '--lengthbegin'):
            options.passwd_length_begin = int(arg)
        elif opt in ('-E', '--lengthend'):
            options.passwd_length_end = int(arg)
        elif opt in ('-w', '--wordlist'):
            options.wordlist = arg
        elif opt in ('-a', '--alpha'):
            options.alpha = True
        elif opt in ('-n', '--numeric'):
            options.numeric = True
        elif opt in ('-b', '--symbols'):
            options.symbols = True
        elif opt in ('-g', '--gridsize'):
            options.gridX = int(arg)
            options.gridY = int(arg)
            
    if args[1] in ("pin", "PIN"):
        options.lock = options.PIN
    elif args[1] in ("gesture", "GESTURE"):
        options.lock = options.GESTURE
    else:
        usage()
        
    options.passwd = args[2]
    if len(args) == 4:
        options.salt = struct.pack('>q', long(args[3])).encode("hex")
        options.strsalt = args[3]
    if args[0] in ("crack", "CRACK"):
        handle_crack(options)
    elif args[0] in ("generate", "GENERATE"):
        handle_generate(options)
    else:
        usage()
        
if __name__ == "__main__":
    main()        