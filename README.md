CRYPTO_ASSIGNMENT #2
# format-preserving-encryption

Name: Ram Chandra Jangir

Roll Number : CS21M517

Registered Mail ID: contactjangir@gmail.com

---------------------------------------------------------

How to compile and run the program:


**Step-1 :**


Clone this project using below command and you will get below list of files.

           git clone https://github.com/contactjangir/format-preserving-encryption.git

           cd format-preserving-encryption


format-preserving-encryption $ tree

.

├── credit_card_enc_dec_output.txt      -->  I have run pie binary and output is stored in this file.

├── fpe.c

├── fpe.h

├── Makefile

├── Ram-Assignment-1.pdf

├── ram_fpe                             --> This is my precompiled program binary, you may run directly too. 

└── README.md

0 directories, 7 files



**Step-2 :**


It is already having a precompiled binary ram_fpe which can be run directly on Ubuntu system.

OR

How to compile

format-preserving-encryption $ make

gcc fpe.c -lm -lcrypto -o ram_fpe



**Step-3 :**


How to run this program

**format-preserving-encryption $ ./ram_fpe 2b7e151628aed2a6abf7158809cf4f3c 4514560001851363**

##############################################################

    Block Cipher Modes of Operation

         Format-Preserving Encryption

##############################################################

FF1-Based on AES with Block Size as 128

Key is  2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c

Radix = 10
--------------------------------------------------------------

Credit Card Number is < 4 5 1 4 5 6 0 0 0 1 8 5 1 3 6 3>

Tweak is  45 14 56 13 63

Issuer Identification Number is 4 5 1 4 5 6 >

Transaction Identification Number is 1 3 6 3 >

Plaintext is < 0 0 0 1 8 5>

FF1_encrypt()
--------------

X is 0 0 0 1 8 5

Tweak is  45 14 56 13 63

Step 1:
        u is 3, v is 3

Step 2:
         A is    0 0 0

         B is    1 8 5

Step 3:
         b is    2

Step 4:
         d is    8

Step 5:

         P is    [ 1 2 1 0 0 10 10 3 0 0 0 6 0 0 0 5 ]

Round #0

        Step 6.i

                 Q is   [ 69 20 86 19 99 0 0 0 0 0 0 0 0 0 0 185 ]

        Step 6.ii

                 R is    [11 230 58 161 37 222 80 252 244 183 113 50 75 74 124 187 ]

        Step 6.iii

                 S is   be63aa125de50fc

        Step 6.iv

                 y is    BE63AA125DE50FC

        Step 6.v

                 m is    3

        Step 6.vi

                 c is   556

        Step 6.vii

                 C is   5 5 6

        Step 6.viii

                 A is   1 8 5

        Step 6.ix

                 B is   5 5 6

Round #1

        Step 6.i

                 Q is   [ 69 20 86 19 99 0 0 0 0 0 0 0 0 1 2 44 ]

        Step 6.ii

                 R is    [235 105 83 156 62 119 80 178 166 167 213 175 36 40 134 11 ]

        Step 6.iii

                 S is   eb69539c3e7750b2

        Step 6.iv

                 y is    EB69539C3E7750B2

        Step 6.v

                 m is    3

        Step 6.vi

                 c is   443

        Step 6.vii

                 C is   4 4 3

        Step 6.viii

                 A is   5 5 6

        Step 6.ix

                 B is   4 4 3

Round #2

        Step 6.i

                 Q is   [ 69 20 86 19 99 0 0 0 0 0 0 0 0 2 1 187 ]

        Step 6.ii

                 R is    [62 110 159 3 56 176 74 220 227 63 9 234 101 47 108 233 ]

        Step 6.iii

                 S is   3e6e9f338b04adc

        Step 6.iv

                 y is    3E6E9F0338B04ADC


        Step 6.v

                 m is    3


        Step 6.vi

                 c is   616


        Step 6.vii

                 C is   6 1 6


        Step 6.viii

                 A is   4 4 3


        Step 6.ix

                 B is   6 1 6


Round #3

        Step 6.i

                 Q is   [ 69 20 86 19 99 0 0 0 0 0 0 0 0 3 2 104 ]

        Step 6.ii

                 R is    [233 224 134 197 12 172 18 171 157 153 120 216 154 73 63 130 ]

        Step 6.iii

                 S is   e9e086c5cac12ab

        Step 6.iv

                 y is    E9E086C50CAC12AB

        Step 6.v

                 m is    3

        Step 6.vi

                 c is   334

        Step 6.vii

                 C is   3 3 4

        Step 6.viii

                 A is   6 1 6

        Step 6.ix

                 B is   3 3 4


Round #4

        Step 6.i

                 Q is   [ 69 20 86 19 99 0 0 0 0 0 0 0 0 4 1 78 ]

        Step 6.ii

                 R is    [113 195 29 11 54 131 5 176 38 107 220 31 83 67 130 195 ]

        Step 6.iii

                 S is   71c31db36835b0

        Step 6.iv

                 y is    71C31D0B368305B0

        Step 6.v

                 m is    3

        Step 6.vi

                 c is   400

        Step 6.vii

                 C is   4 0 0

        Step 6.viii

                 A is   3 3 4

        Step 6.ix

                 B is   4 0 0


Round #5

        Step 6.i

                 Q is   [ 69 20 86 19 99 0 0 0 0 0 0 0 0 5 1 144 ]

        Step 6.ii

                 R is    [236 10 100 80 2 121 158 82 50 111 165 38 31 221 195 222 ]

        Step 6.iii

                 S is   eca64502799e52

        Step 6.iv

                 y is    EC0A645002799E52

        Step 6.v

                 m is    3

        Step 6.vi

                 c is   888

        Step 6.vii

                 C is   8 8 8

        Step 6.viii

                 A is   4 0 0

        Step 6.ix

                 B is   8 8 8


Round #6

        Step 6.i

                 Q is   [ 69 20 86 19 99 0 0 0 0 0 0 0 0 6 3 120 ]

        Step 6.ii

                 R is    [227 166 60 152 255 121 14 149 114 154 26 19 233 128 20 0 ]

        Step 6.iii

                 S is   e3a63c98ff79e95

        Step 6.iv

                 y is    E3A63C98FF790E95

        Step 6.v

                 m is    3

        Step 6.vi

                 c is   989

        Step 6.vii

                 C is   9 8 9

        Step 6.viii

                 A is   8 8 8

        Step 6.ix

                 B is   9 8 9


Round #7

        Step 6.i

                 Q is   [ 69 20 86 19 99 0 0 0 0 0 0 0 0 7 3 221 ]

        Step 6.ii

                 R is    [87 203 49 160 27 165 129 27 227 152 8 54 7 172 0 51 ]

        Step 6.iii

                 S is   57cb31a01ba5811b

        Step 6.iv
   
              y is    57CB31A01BA5811B

        Step 6.v

                 m is    3

        Step 6.vi

                 c is   195

        Step 6.vii

                 C is   1 9 5

        Step 6.viii

                 A is   9 8 9

        Step 6.ix

                 B is   1 9 5


Round #8

        Step 6.i

                 Q is   [ 69 20 86 19 99 0 0 0 0 0 0 0 0 8 0 195 ]

        Step 6.ii

                 R is    [231 127 114 173 57 223 9 157 160 207 245 135 101 68 23 218 ]

        Step 6.iii

                 S is   e77f72ad39df99d

        Step 6.iv

                 y is    E77F72AD39DF099D

        Step 6.v

                 m is    3

        Step 6.vi

                 c is   490

        Step 6.vii

                 C is   4 9 0

        Step 6.viii

                 A is   1 9 5

        Step 6.ix

                 B is   4 9 0


Round #9

        Step 6.i

                 Q is   [ 69 20 86 19 99 0 0 0 0 0 0 0 0 9 1 234 ]

        Step 6.ii

                 R is    [48 187 21 199 245 250 39 136 251 105 127 144 246 5 100 218 ]

        Step 6.iii

                 S is   30bb15c7f5fa2788

        Step 6.iv

                 y is    30BB15C7F5FA2788

        Step 6.v

                 m is    3

        Step 6.vi

                 c is   035

        Step 6.vii

                 C is   0 3 5

        Step 6.viii

                 A is   4 9 0

        Step 6.ix

                 B is   0 3 5

        Step 7


CIPHERTEXT ( A||B ) is  4 9 0 0 3 5

ciphertext: 490035


 ********************************************************

ciphertext: 490035

Encrypted Credit Card Number :  4 5 1 4 5 6 4 9 0 0 3 5 1 3 6 3


 ********************************************************


 We start Decrypting the cipher back

FF1_decrypt()
--------------

X is 4 9 0 0 3 5

Tweak is  45 14 56 13 63

Step 1:

        u is 3, v is 3

Step 2:

         A is    4 9 0

         B is    0 3 5

Step 3:

         b is    2

Step 4:

         d is    8

Step 5:

         P is    [ 1 2 1 0 0 10 10 3 0 0 0 6 0 0 0 5 ]


Round #9

        Step 6.i

                 Q is   [ 69 20 86 19 99 0 0 0 0 0 0 0 0 9 1 234 ]

        Step 6.ii

                 R is    [48 187 21 199 245 250 39 136 251 105 127 144 246 5 100 218 ]

        Step 6.iii

                 S is   30bb15c7f5fa2788

        Step 6.iv

                 y is    30BB15C7F5FA2788

        Step 6.v

                 m is    3

        Step 6.vi

                 c is   490

        Step 6.vii

                 C is   4 9 0

        Step 6.viii

                 A is   1 9 5

        Step 6.ix

                 B is   4 9 0

Round #8

        Step 6.i

                 Q is   [ 69 20 86 19 99 0 0 0 0 0 0 0 0 8 0 195 ]

        Step 6.ii

                 R is    [231 127 114 173 57 223 9 157 160 207 245 135 101 68 23 218 ]

        Step 6.iii

                 S is   e77f72ad39df99d

        Step 6.iv

                 y is    E77F72AD39DF099D

        Step 6.v

                 m is    3

        Step 6.vi

                 c is   195

        Step 6.vii

                 C is   1 9 5

        Step 6.viii

                 A is   9 8 9

        Step 6.ix

                 B is   1 9 5

Round #7

        Step 6.i

                 Q is   [ 69 20 86 19 99 0 0 0 0 0 0 0 0 7 3 221 ]

        Step 6.ii

                 R is    [87 203 49 160 27 165 129 27 227 152 8 54 7 172 0 51 ]

        Step 6.iii

                 S is   57cb31a01ba5811b

        Step 6.iv

                 y is    57CB31A01BA5811B

        Step 6.v

                 m is    3

        Step 6.vi

                 c is   989

        Step 6.vii

                 C is   9 8 9

        Step 6.viii

                 A is   8 8 8

        Step 6.ix

                 B is   9 8 9


Round #6

        Step 6.i

                 Q is   [ 69 20 86 19 99 0 0 0 0 0 0 0 0 6 3 120 ]

        Step 6.ii

                 R is    [227 166 60 152 255 121 14 149 114 154 26 19 233 128 20 0 ]

        Step 6.iii

                 S is   e3a63c98ff79e95

        Step 6.iv

                 y is    E3A63C98FF790E95

        Step 6.v

                 m is    3

        Step 6.vi

                 c is   888

        Step 6.vii

                 C is   8 8 8

        Step 6.viii

                 A is   4 0 0

        Step 6.ix

                 B is   8 8 8

Round #5

        Step 6.i

                 Q is   [ 69 20 86 19 99 0 0 0 0 0 0 0 0 5 1 144 ]

        Step 6.ii

                 R is    [236 10 100 80 2 121 158 82 50 111 165 38 31 221 195 222 ]

        Step 6.iii

                 S is   eca64502799e52

        Step 6.iv

                 y is    EC0A645002799E52

        Step 6.v

                 m is    3

        Step 6.vi

                 c is   400

        Step 6.vii

                 C is   4 0 0

        Step 6.viii

                 A is   3 3 4

        Step 6.ix

                 B is   4 0 0


Round #4

        Step 6.i

                 Q is   [ 69 20 86 19 99 0 0 0 0 0 0 0 0 4 1 78 ]

        Step 6.ii

                 R is    [113 195 29 11 54 131 5 176 38 107 220 31 83 67 130 195 ]

        Step 6.iii

                 S is   71c31db36835b0

        Step 6.iv

                 y is    71C31D0B368305B0

        Step 6.v

                 m is    3

        Step 6.vi

                 c is   334

        Step 6.vii

                 C is   3 3 4

        Step 6.viii

                 A is   6 1 6

        Step 6.ix

                 B is   3 3 4

Round #3

        Step 6.i

                 Q is   [ 69 20 86 19 99 0 0 0 0 0 0 0 0 3 2 104 ]

        Step 6.ii

                 R is    [233 224 134 197 12 172 18 171 157 153 120 216 154 73 63 130 ]

        Step 6.iii

                 S is   e9e086c5cac12ab

        Step 6.iv

                 y is    E9E086C50CAC12AB

        Step 6.v

                 m is    3

        Step 6.vi

                 c is   616

        Step 6.vii

                 C is   6 1 6

        Step 6.viii

                 A is   4 4 3

        Step 6.ix

                 B is   6 1 6


Round #2

        Step 6.i

                 Q is   [ 69 20 86 19 99 0 0 0 0 0 0 0 0 2 1 187 ]

        Step 6.ii

                 R is    [62 110 159 3 56 176 74 220 227 63 9 234 101 47 108 233 ]

        Step 6.iii

                 S is   3e6e9f338b04adc

        Step 6.iv

                 y is    3E6E9F0338B04ADC

        Step 6.v

                 m is    3

        Step 6.vi

                 c is   443

        Step 6.vii

                 C is   4 4 3

        Step 6.viii

                 A is   5 5 6

        Step 6.ix

                 B is   4 4 3

Round #1

        Step 6.i

                 Q is   [ 69 20 86 19 99 0 0 0 0 0 0 0 0 1 2 44 ]

        Step 6.ii

                 R is    [235 105 83 156 62 119 80 178 166 167 213 175 36 40 134 11 ]

        Step 6.iii

                 S is   eb69539c3e7750b2

        Step 6.iv

                 y is    EB69539C3E7750B2

        Step 6.v

                 m is    3

        Step 6.vi

                 c is   556

        Step 6.vii

                 C is   5 5 6

        Step 6.viii

                 A is   1 8 5

        Step 6.ix

                 B is   5 5 6


Round #0

        Step 6.i

                 Q is   [ 69 20 86 19 99 0 0 0 0 0 0 0 0 0 0 185 ]

        Step 6.ii

                 R is    [11 230 58 161 37 222 80 252 244 183 113 50 75 74 124 187 ]

        Step 6.iii

                 S is   be63aa125de50fc

        Step 6.iv

                 y is    BE63AA125DE50FC

        Step 6.v

                 m is    3

        Step 6.vi

                 c is   185

        Step 6.vii

                 C is   1 8 5

        Step 6.viii

                 A is   0 0 0

        Step 6.ix

                 B is   1 8 5

--------------------------------------------------------------

Decrypted Card Number

Plaintext: < 4 5 1 4 5 6 0 0 0 1 8 5 1 3 6 3 >

