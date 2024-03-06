from AESdecryptfunc import * 
import math 
import io


if len(sys.argv) is not 3:
    sys.exit("Error, script needs two command-line arguments. (Ciphertext.txt File and plainhex.txt File)")
PassPhrase=""

while(len(PassPhrase)!=16):
    print("Enter in the 16 character passphrase to decrypt your text file %s" %sys.argv[1])
    PassPhrase=input()
    if(len(PassPhrase)<16):#check if less than 16 characters, if so add one space character until 16 chars
        while(len(PassPhrase)!=16):
            PassPhrase=PassPhrase+"\00"
    if(len(PassPhrase)>16):#check if bigger than 16 characters, if so then truncate it to be only 16 chars from [0:16]
        print("Your passphrase was larger than 16, truncating passphrase.")
        PassPhrase=PassPhrase[0:16]

#open ciphertext.txt file to read and decrypt
file=open(sys.argv[1], "r")
message=(file.read())
print("Inside your ciphertext message is:\n%s\n" % message)
file.close()


start=0
end=32
length=len(message)
loopmsg=0.00
loopmsg=math.ceil(length/32)+1
outputhex=""
asciioutput=""

#need to setup roundkeys here
PassPhrase=BitVector(textstring=PassPhrase)
roundkey1=findroundkey(PassPhrase.get_bitvector_in_hex(),1)
roundkey2=findroundkey(roundkey1,2)
roundkey3=findroundkey(roundkey2,3)
roundkey4=findroundkey(roundkey3,4)
roundkey5=findroundkey(roundkey4,5)
roundkey6=findroundkey(roundkey5,6)
roundkey7=findroundkey(roundkey6,7)
roundkey8=findroundkey(roundkey7,8)
roundkey9=findroundkey(roundkey8,9)
roundkey10=findroundkey(roundkey9,10)
roundkeys=[roundkey1,roundkey2,roundkey3,roundkey4,roundkey5,roundkey6,roundkey7,roundkey8,roundkey9,roundkey10]

FILEOUT = io.open(sys.argv[2], 'w', encoding='utf-8')

# loop to encrypt all segments of the message
for y in range(1, loopmsg): 
    plaintextseg = message[start:end]

    # add round key
    bv1 = BitVector(hexstring=plaintextseg)
    bv2 = BitVector(hexstring=roundkeys[9])
    resultbv = bv1 ^ bv2
    myhexstring = resultbv.get_bitvector_in_hex()

    #inverse shift row
    myhexstring=invshiftrow(myhexstring)

    #inverse subbyte
    myhexstring=invsubbyte(myhexstring)

    for x in range(8, -1, -1):
        # add roundkey for current round
        bv1 = BitVector(hexstring=myhexstring)
        bv2 = BitVector(hexstring=roundkeys[x])
        resultbv = bv1 ^ bv2
        myhexstring = resultbv.get_bitvector_in_hex()

        # mix column
        bv3 = BitVector(hexstring=myhexstring)
        myhexstring=invmixcolumn(bv3)

        # shift rows
        myhexstring = invshiftrow(myhexstring)

        # sub byte
        myhexstring = invsubbyte(myhexstring)

    #add initial round key
    bv1 = BitVector(hexstring=myhexstring)
    bv2 = PassPhrase
    resultbv = bv1 ^ bv2
    myhexstring = resultbv.get_bitvector_in_hex()

    start = start + 32 #increment start pointer
    end = end + 32 #increment end pointer

    replacementptr = 0
    while (replacementptr < len(myhexstring)):
        if (myhexstring[replacementptr:replacementptr + 2] == '0d'):
            myhexstring = myhexstring[0:replacementptr] + myhexstring[replacementptr+2:len(myhexstring)]
        else:
            replacementptr = replacementptr + 2

    outputhex = BitVector(hexstring=myhexstring)
    asciioutput = outputhex.get_bitvector_in_ascii()
    asciioutput=asciioutput.replace('\x00','')
    FILEOUT.write(asciioutput)

FILEOUT.close()

file2=io.open(sys.argv[2], "r", encoding='utf-8')
print("The decrypted message for the entire ciphertext is:\n%s\n" % file2.read())
file2.close()