/*
Batch : 3 
Mahima Pant        - BT17CSE040
Mugdha Kolhe       - BT17CSE043
Grishma Mahapurush - BT17CSE097

Topic : An efficient and secure searchable public key encryption scheme with privacy protection for cloud storage
Functions :
1. Setup - It takes as input the security parameter λ and generates the public parameters Para.
2. KeyGen - It takes as input the public parameters Para and generates the two public/secret key pairs (P Ku,sku), (P Ks,sks) for DU and DS, respectively
3. SPE_PP -  It takes as input the public parameters Para, the DU’s public key P Ku, the DS’s secret key sks and the keyword set W, and generates theciphertext dataset C of W.
4. Trapdoor -  It takes as input the public parameters Para, the DU’s public key P Ku, the DS’s secret key sks and the keyword set W, and generates the ciphertext dataset C of W.
5. Test - : It takes as input the public parameter Para, the trapdoor Twj of wj and the keyword ciphertext set C, and outputs 1 if the ciphertext Cwi and Twj contain the same keyword and otherwise outputs 0.
            For test purpose :
            E3 = E2/E1 = e(ri P, h2(wj)abP)
Output :  1 - If the word to be searched wj is found in word dataset wi
          0 - If the word to be searched wj is not found in word dataset wi
          The output also displays the time taken by each function used in scheme

To run the program : g++ SPE_PP.cpp -lpbc -lgmp
                   : ./a.out    





*/
//------------------------------------------------Code---------------------------------------------------//
#include <cstring>
#include <fstream>
#ifndef SHA256_H
#define SHA256_H
#include <string>
#include <iostream>
#include <pbc/pbc.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmp.h>
#include <time.h>
#include <assert.h>
#include <bits/stdc++.h>
using namespace std;

//--------------------------------------------SHA 256 ALGORITHM----------------------------------------------//
class SHA256
{
protected:
    typedef unsigned char uint8;
    typedef unsigned int uint32;
    typedef unsigned long long uint64;
 
    const static uint32 sha256_k[];
    static const unsigned int SHA224_256_BLOCK_SIZE = (512/8);
public:
    void init();
    void update(const unsigned char *message, unsigned int len);
    void final(unsigned char *digest);
    static const unsigned int DIGEST_SIZE = ( 256 / 8);
 
protected:
    void transform(const unsigned char *message, unsigned int block_nb);
    unsigned int m_tot_len;
    unsigned int m_len;
    unsigned char m_block[2*SHA224_256_BLOCK_SIZE];
    uint32 m_h[8];
};
 
string sha256(string input);
 
#define SHA2_SHFR(x, n)    (x >> n)
#define SHA2_ROTR(x, n)   ((x >> n) | (x << ((sizeof(x) << 3) - n)))
#define SHA2_ROTL(x, n)   ((x << n) | (x >> ((sizeof(x) << 3) - n)))
#define SHA2_CH(x, y, z)  ((x & y) ^ (~x & z))
#define SHA2_MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define SHA256_F1(x) (SHA2_ROTR(x,  2) ^ SHA2_ROTR(x, 13) ^ SHA2_ROTR(x, 22))
#define SHA256_F2(x) (SHA2_ROTR(x,  6) ^ SHA2_ROTR(x, 11) ^ SHA2_ROTR(x, 25))
#define SHA256_F3(x) (SHA2_ROTR(x,  7) ^ SHA2_ROTR(x, 18) ^ SHA2_SHFR(x,  3))
#define SHA256_F4(x) (SHA2_ROTR(x, 17) ^ SHA2_ROTR(x, 19) ^ SHA2_SHFR(x, 10))
#define SHA2_UNPACK32(x, str)                 \
{                                             \
    *((str) + 3) = (uint8) ((x)      );       \
    *((str) + 2) = (uint8) ((x) >>  8);       \
    *((str) + 1) = (uint8) ((x) >> 16);       \
    *((str) + 0) = (uint8) ((x) >> 24);       \
}
#define SHA2_PACK32(str, x)                   \
{                                             \
    *(x) =   ((uint32) *((str) + 3)      )    \
           | ((uint32) *((str) + 2) <<  8)    \
           | ((uint32) *((str) + 1) << 16)    \
           | ((uint32) *((str) + 0) << 24);   \
}
#endif
const unsigned int SHA256::sha256_k[64] = //UL = uint32
            {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
             0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
             0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
             0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
             0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
             0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
             0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
             0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
             0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
             0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
             0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
             0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
             0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
             0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
             0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
             0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
 
void SHA256::transform(const unsigned char *message, unsigned int block_nb)
{
    uint32 w[64];
    uint32 wv[8];
    uint32 t1, t2;
    const unsigned char *sub_block;
    int i;
    int j;
    for (i = 0; i < (int) block_nb; i++) {
        sub_block = message + (i << 6);
        for (j = 0; j < 16; j++) {
            SHA2_PACK32(&sub_block[j << 2], &w[j]);
        }
        for (j = 16; j < 64; j++) {
            w[j] =  SHA256_F4(w[j -  2]) + w[j -  7] + SHA256_F3(w[j - 15]) + w[j - 16];
        }
        for (j = 0; j < 8; j++) {
            wv[j] = m_h[j];
        }
        for (j = 0; j < 64; j++) {
            t1 = wv[7] + SHA256_F2(wv[4]) + SHA2_CH(wv[4], wv[5], wv[6])
                + sha256_k[j] + w[j];
            t2 = SHA256_F1(wv[0]) + SHA2_MAJ(wv[0], wv[1], wv[2]);
            wv[7] = wv[6];
            wv[6] = wv[5];
            wv[5] = wv[4];
            wv[4] = wv[3] + t1;
            wv[3] = wv[2];
            wv[2] = wv[1];
            wv[1] = wv[0];
            wv[0] = t1 + t2;
        }
        for (j = 0; j < 8; j++) {
            m_h[j] += wv[j];
        }
    }
}
 
void SHA256::init()
{
    m_h[0] = 0x6a09e667;
    m_h[1] = 0xbb67ae85;
    m_h[2] = 0x3c6ef372;
    m_h[3] = 0xa54ff53a;
    m_h[4] = 0x510e527f;
    m_h[5] = 0x9b05688c;
    m_h[6] = 0x1f83d9ab;
    m_h[7] = 0x5be0cd19;
    m_len = 0;
    m_tot_len = 0;
}
 
void SHA256::update(const unsigned char *message, unsigned int len)
{
    unsigned int block_nb;
    unsigned int new_len, rem_len, tmp_len;
    const unsigned char *shifted_message;
    tmp_len = SHA224_256_BLOCK_SIZE - m_len;
    rem_len = len < tmp_len ? len : tmp_len;
    memcpy(&m_block[m_len], message, rem_len);
    if (m_len + len < SHA224_256_BLOCK_SIZE) {
        m_len += len;
        return;
    }
    new_len = len - rem_len;
    block_nb = new_len / SHA224_256_BLOCK_SIZE;
    shifted_message = message + rem_len;
    transform(m_block, 1);
    transform(shifted_message, block_nb);
    rem_len = new_len % SHA224_256_BLOCK_SIZE;
    memcpy(m_block, &shifted_message[block_nb << 6], rem_len);
    m_len = rem_len;
    m_tot_len += (block_nb + 1) << 6;
}
 
void SHA256::final(unsigned char *digest)
{
    unsigned int block_nb;
    unsigned int pm_len;
    unsigned int len_b;
    int i;
    block_nb = (1 + ((SHA224_256_BLOCK_SIZE - 9)
                     < (m_len % SHA224_256_BLOCK_SIZE)));
    len_b = (m_tot_len + m_len) << 3;
    pm_len = block_nb << 6;
    memset(m_block + m_len, 0, pm_len - m_len);
    m_block[m_len] = 0x80;
    SHA2_UNPACK32(len_b, m_block + pm_len - 4);
    transform(m_block, block_nb);
    for (i = 0 ; i < 8; i++) {
        SHA2_UNPACK32(m_h[i], &digest[i << 2]);
    }
}
 
string sha256(string input)
{
    unsigned char digest[SHA256::DIGEST_SIZE];
    memset(digest,0,SHA256::DIGEST_SIZE);
 
    SHA256 ctx = SHA256();
    ctx.init();
    ctx.update( (unsigned char*)input.c_str(), input.length());
    ctx.final(digest);
 
    char buf[2*SHA256::DIGEST_SIZE+1];
    buf[2*SHA256::DIGEST_SIZE] = 0;
    for (int i = 0; i < SHA256::DIGEST_SIZE; i++)
        sprintf(buf+i*2, "%02x", digest[i]);
    return string(buf);
}

//-----------------------------------DATA STRUCTURES USED IN THE SCHEME-----------------------------------//

typedef struct setup_output {       // DATA STRUCTURE TO STORE THE PUBLIC PARAMETERS OF THE WORD WHICH IS SEARCHED BY DATA USER

    
    mpz_t q;    // order of group (r)
    pairing_t pairing; 
    pbc_param_t par;
    element_t g1,g2,gt;
    element_t P;    // Generator


}setup_result;
setup_result globle_setup;           // DATA STRUCTURE TO STORE THE KEYS OF DATA USER AND DATA SENDER
typedef struct Keys {

    element_t PKu,PKs;
    element_t SKu,SKs;

}keys;

keys MyKeys;
element_t global_r;
typedef struct Ciphertexts {             // DATA STRUCTURE TO STORE THE CIPHERTEXT OF ALL WORDS WHICH ARE PROVIDED BY DATA SENDER

        element_t* Ciphertext1;
        element_t* Ciphertext2;
        element_t* Ciphertext3;
}CT;

CT Ciphers;
typedef struct Trapdoor {               // DATA STRUCTURE TO STORE THE TRAPDOOR OF THE WORD WHICH IS SEARCHED BY DATA USER

        element_t T1w;
        element_t T2w;
}T;

T trapdoor;

//--------------------------------------------STRING TO BINARY FUNCTION--------------------------//
string strToBinary(string s)
{
    int n = s.length();
  
    string result="";
    for (int i = 0; i <= n; i++)
    {
        // convert each char to
        // ASCII value
        int val = int(s[i]);
  
        // Convert ASCII value to binary
        string bin = "";
        while (val > 0)
        {
            (val % 2)? bin.push_back('1') :
                       bin.push_back('0');
            val /= 2;
        }
        reverse(bin.begin(), bin.end());
        result+=bin;
    
    }
    return result;
}

//-------------------------------------------KEY GENERATION--------------------------------//
void KeyGen()
{
    cout<<"Starting the Key generation function"<<endl;
    cout<<"=============================================="<<endl<<endl;
    element_t a,b;
    element_init_Zr(a, globle_setup.pairing);
    element_init_Zr(b, globle_setup.pairing);
    element_random(a);
    element_random(b);
    element_init_G1(MyKeys.PKu, globle_setup.pairing);
    element_init_G1(MyKeys.PKs, globle_setup.pairing);      
    element_mul_zn(MyKeys.PKu, globle_setup.P, a);             // Data user public key PKu= a.P
    element_mul_zn(MyKeys.PKs, globle_setup.P, b);             // Data sender public key PKs= b.P
    element_printf("\nData user public key :  %B\n", MyKeys.PKu);
    element_printf("\nData sender public key : %B\n", MyKeys.PKs);
    element_init_Zr(MyKeys.SKu, globle_setup.pairing);
    element_init_Zr(MyKeys.SKs, globle_setup.pairing);
    
    element_set(MyKeys.SKu, a);
    element_set(MyKeys.SKs, b);
    element_printf("\nData user secret key :  %B\n", MyKeys.SKu);
    element_printf("\nData sender secret key : %B\n", MyKeys.SKs);
    cout<<"=============================================="<<endl;


}

//-------------------------------------------HASH FUNCTIONS------------------------------------//
void hash1(element_t e,element_t h1_val)    // h1 : G1 -> Z*q
{
    
     unsigned char data[100];
    element_t s;
    element_init_Zr(s, globle_setup.pairing);

    int x = element_to_bytes(data,e);
    string message="";
    for(int i=0;i<100;i++)
    {
        message+=data[i];
    }
    string hash_value = sha256(message);
    int len = hash_value.length();
    unsigned char result[len];
    for(int i=0;i<len;i++)
    {
        result[i]=hash_value[i];
    }
    element_from_bytes(s,result);
    element_set(h1_val,s);
 
}

void hash2(string str,element_t h2_val)         // h2 : (0,1)* -> Z*q
{
    
     
    element_t s;
    
    
    string hash_value = sha256(str);        // Applying SHA256 on the string str
    int len = hash_value.length();
    unsigned char result[len];
    for(int i=0;i<len;i++)
    {
        result[i]=hash_value[i];
    }
    element_init_Zr(s, globle_setup.pairing);
   
    element_from_bytes(s,result);
    element_set(h2_val, s);

}

//------------------------------------------------------SETUP FUNCTION-------------------------------------//
void setup(mpz_t security_parameter) 
{
    pairing_t pairing; 
    pbc_param_t par;
    mpz_t rb; 
    mpz_init(rb);
    
    int rbits=160;
    int qbits=412;
    pbc_param_init_a_gen(globle_setup.par,rbits,qbits);  // Initializing A type curve
 
    pairing_init_pbc_param(globle_setup.pairing, globle_setup.par);
    pairing_init_pbc_param(pairing, globle_setup.par);
    printf("Using type A curve with parameters\n");
    cout<<"=============================================="<<endl;
    pbc_param_out_str(stdout, globle_setup.par);    // Printing the A type curve parameters
    cout<<"=============================================="<<endl;

    FILE *stream;
    stream = fopen("a_param.txt", "w+");    
    pbc_param_out_str(stream, globle_setup.par);
    fclose(stream);


    
    FILE *reading;
    char buff[1024];

    reading = fopen("a_param.txt", "r");
    fscanf(reading, "%s", buff);
    fgets(buff, 1024, (FILE*)reading);
    
    fgets(buff, 1024, (FILE*)reading);
    

    fgets(buff, 1024, (FILE*)reading);
    
    fgets(buff, 1024, (FILE*)reading);
    char * r= buff+2;
    mpz_init(globle_setup.q);
    mpz_init_set_str(globle_setup.q,r,10);      // Storing the order of curve in the structure
    cout<<"Starting the Setup function"<<endl;
    cout<<"=============================================="<<endl<<endl;
    gmp_printf("Order of the G1 group : %Zd\n",globle_setup.q);
    element_t g1, g2, gt,p;

    element_init_G1(g1, pairing);
    element_init_G1(g2, pairing);
   
    element_init_GT(gt, pairing);
    
    element_random(g1);     // Picking random element from G1 curve
    element_random(g2);     // Picking another random element from G1 curve

    element_init_G1(globle_setup.g1,pairing);
    element_init_G1(globle_setup.g2,pairing);

    element_set(globle_setup.g1,g1);
    element_set(globle_setup.g2,g2);

    element_printf("Element of G1 group g1: %B\n", g1);

    
    element_printf("Another element of G1 group g2: %B\n", g2);

    element_pairing(gt,g1,g2);

    element_init_GT(globle_setup.gt,pairing);
    element_set(globle_setup.gt,gt);

    element_printf("Applying symmetric bilinear pairing :g1 X g1, gt= %B\n", gt);
    element_init_G1(globle_setup.P,pairing);    
    element_init_G1(p, pairing);
    element_random(p);
    element_set(globle_setup.P,p);          // Storing the generator of A curve in the global structure
    element_printf("\nGenerator selected: %B\n", p);
    mpz_t index;
    mpz_init(index);
    mpz_set_ui(index,1);
    
    
    element_t h1_val,h2_val;
    element_init_Zr(h1_val,globle_setup.pairing);
    element_init_Zr(h2_val,globle_setup.pairing);


    hash1(p,h1_val);    // h1 : G1 -> Z*q
    
    string msg = "Hello123";        // Message to be hashed in h2
    string bin = strToBinary(msg);  // Converting this message to binary to feed it to h2
    cout<<bin<<endl;
    hash2(bin,h2_val);          // h2 : (0,1)* -> Z*q
    element_printf("After hashing element: %B using h1 : G1 -> Z*q\n", p);
    element_printf("Hashed value : %B\n",h1_val);
    cout<<"After hashing message: "<<msg<<" using h2 : (0,1)* -> Z*q\n";
    element_printf("Hashed value : %B\n",h2_val);
    cout<<"=============================================="<<endl<<endl;

}
element_t  hashed;
element_t* rand_vec;
//--------------------------------------SPE_PP FUCNTION---------------------------------------------------//
void SPE_PP(vector<string> words)
{
    cout<<endl<<endl;
    cout<<"=============================================="<<endl;
    cout<<"Starting the SPE_PP function by DS"<<endl;
    cout<<"=============================================="<<endl<<endl;
    
    //Ciphertext allocation
    Ciphers.Ciphertext1 = (element_t*)malloc(sizeof(element_t)*words.size());
    Ciphers.Ciphertext2 = (element_t*)malloc(sizeof(element_t)*words.size());
    Ciphers.Ciphertext3 = (element_t*)malloc(sizeof(element_t)*words.size());
    
    //dynamic array to store values of r
    rand_vec = (element_t*)malloc(sizeof(element_t)*words.size());
    
    //declarations and initializations
    element_t r , k, mul_value, power, h2_value;
    element_t DH_SSK_key,Q,pair_value;
    element_init_G1(DH_SSK_key, globle_setup.pairing);
    element_init_G1(Q, globle_setup.pairing);
    element_init_GT(pair_value, globle_setup.pairing);
    element_init_Zr(r,globle_setup.pairing);
    element_init_Zr(k,globle_setup.pairing);
    element_init_Zr(power,globle_setup.pairing);
    element_init_Zr(h2_value ,globle_setup.pairing);
    
    //Initialization of Ciphertext
    for(int i=0;i<words.size();i++)
    {
        element_init_G1(Ciphers.Ciphertext1[i],globle_setup.pairing);
        element_init_G1(Ciphers.Ciphertext2[i],globle_setup.pairing);
        element_init_GT(Ciphers.Ciphertext3[i],globle_setup.pairing);
        element_init_Zr(rand_vec[i],globle_setup.pairing);
    }
    
    
    
    //Loop runs for each word
    for(int i=0;i<words.size();i++)
    {
        element_random(r);  //ri belongs to zr
        element_printf("Random number %B :\n",r);     
        element_set(rand_vec[i],r); //r value stored in vector 
        
        //Calculation of C1               
        element_mul_zn(Ciphers.Ciphertext1[i], globle_setup.P, r);  //C1=P*r
        
        //Calculation of C2
        element_mul_zn(DH_SSK_key, MyKeys.SKs, MyKeys.PKu);     //DH-SSK=abP  
        hash1(DH_SSK_key,k);    //k=h1(DH-SSK)      
        element_mul_zn(Q, globle_setup.P, k);  //Q=P*k=P* h1(abP)
        element_mul_zn(Ciphers.Ciphertext2[i], Q, r);   //C2=Q*r
        
        //Calculation of C3
        element_t hashed_val_2;
        element_init_Zr(hashed_val_2, globle_setup.pairing);
        string bin = strToBinary(words[i]);     // Converting this word to binary to feed it to h2       
        hash2(bin,hashed_val_2);                //hashed_val_2=h2(bin)
        element_mul_zn(power, r,hashed_val_2);   //power=hashed_val_2=r*h2(bin)    
        element_pairing(pair_value, MyKeys.PKu, MyKeys.PKs);    //pair_value=PKu*PKs=aP*bP
        element_pow_zn(Ciphers.Ciphertext3[i],pair_value,power);    //C3=pair_value^power
 
       
        //Displaying Ciphertexts
        cout<<"\nFor word: " <<words[i]<<endl;
        cout<<"\nC1w"<<i<<": ";
        element_printf("%B",Ciphers.Ciphertext1[i]);
        cout<<"\n\nC2w"<<i<<": ";
        element_printf("%B",Ciphers.Ciphertext2[i]);
        cout<<"\n\nC3w"<<i<<": ";
        element_printf("%B",Ciphers.Ciphertext3[i]);
    }
}
//--------------------------------------TRAPDOOR FUCNTION---------------------------------------------------//
void Trapdoor(string wordj,vector<string> words)
{
  

   cout<<"=============================================="<<endl;
    cout<<"Starting the Trapdoor by DU"<<endl;
    cout<<"=============================================="<<endl;
    element_t DH_SSK_key,Q;
    element_init_G1(DH_SSK_key, globle_setup.pairing);          // DH_SSK_Key = PKs.SKu
    element_init_G1(Q, globle_setup.pairing);                   // Q = k.P
             
   element_init_Zr(global_r, globle_setup.pairing);
  
    element_t k ;
    element_init_Zr(k, globle_setup.pairing);
  
   
   
    
    element_init_G1(trapdoor.T1w,globle_setup.pairing);         //Initializing T1w and T2w
    element_init_G1(trapdoor.T2w,globle_setup.pairing);

    element_init_Zr(hashed,globle_setup.pairing);   
    element_t r;
    element_init_Zr(r, globle_setup.pairing);               // Initializing random number r
   
    element_random(r);
    element_mul_zn(DH_SSK_key, MyKeys.PKs,MyKeys.SKu);          // DH_SSK_key =SKu.PKs
    element_t temp_2;
    element_init_G1(temp_2, globle_setup.pairing);              // Used for storing 1st operand of T2w
    element_t temp;
    element_init_G1(temp, globle_setup.pairing);                // Used for storing 2nd operand of T2w
    element_mul_zn(trapdoor.T1w, globle_setup.P, r);  // T1w= r*P
    
       
    hash1(DH_SSK_key,k);                // h1(DH_SSK_key) = k =>> Q=k.P
    element_mul_zn(Q,globle_setup.P, k);
    element_mul_zn(temp_2, Q,r);
       

     
    element_t hashed_val_2;
    element_init_Zr(hashed_val_2, globle_setup.pairing);
    string bin = strToBinary(wordj);  // Converting this message to binary to feed it to h2
    hash2(bin,hashed_val_2);
    
    element_set(hashed,hashed_val_2);
   element_mul_zn(temp,DH_SSK_key,hashed_val_2);

    element_add(trapdoor.T2w,temp_2,temp);      // T2w =rj*Q+h2(wj)*sku*P Ks
   
    element_printf("Tw1 : %B\n" ,trapdoor.T1w);
    element_printf("Tw2 : %B\n" ,trapdoor.T2w);       
    int found=0;
    for(int i=0;i<words.size();i++)
    {
        if(words[i]==wordj)
        {
            element_set(global_r,rand_vec[i]);
            found=1;
        }
    }  
    if(found==0)
    {

       element_random(global_r);        // If the word is present store its random number
    }
    
    
}
//--------------------------------------TEST FUCNTION---------------------------------------------------//

int Test(int size)                                // E3= E2/E1 = e(ri P, h2(wj)abP) (simplied formula)     
{
    cout<<endl;
    cout<<"=============================================="<<endl;
    cout<<"Starting the Test by CSP"<<endl;
    cout<<"=============================================="<<endl;
    element_t E3;
   
    element_init_GT(E3,globle_setup.pairing);
   
        for(int i=0;i<size;i++)
        {
               
                //element_pairing(E3,num,den);
            
                
            element_t mul_value ,g,t;
            element_init_G1(mul_value,globle_setup.pairing);
            element_init_G1(t,globle_setup.pairing);
            element_init_Zr(g,globle_setup.pairing);
            element_mul_zn(mul_value,MyKeys.PKu,MyKeys.SKs);
            element_set(g,hashed);                 

            element_mul_zn(mul_value,mul_value,g);
            element_mul_zn(t,globle_setup.P,global_r);
            element_pairing(E3,mul_value,t);                //  e(ri P, h2(wj)abP)= E3
            cout<<"\nFor word number : "<<i+1<<endl<<endl;
            element_printf("E3 : %B\n",E3);
            element_printf("C3 : %B\n",Ciphers.Ciphertext3[i]);
            if(element_cmp(E3,Ciphers.Ciphertext3[i])==0)   // checking if E3= C3 for any word wi
            {
                return 1;
            }
                

     }

    return 0;           // If the word is not present in word dataset return 0
}

//--------------------------------------MAIN FUCNTION---------------------------------------------------//
int main () 
{
    float t1=0, t2=0, t3=0, t4=0, t5=0, t6=0, t7=0,t8=0;
    mpz_t security_parameter;
    mpz_init(security_parameter);
    
    mpz_set_ui(security_parameter, 160);      // Setting lambda =160
    
    t1 = clock();
    setup(security_parameter);
    t2 = clock();
    KeyGen();
    t3= clock();
    vector<string> words;
    int n;
    cout<<"Enter the size of dataset given by Data Sender"<<endl;
    cin>>n;
    string s;
    for(int i=0; i<n; i++)              // Storing the words given by Data Sender
    {
        cout<<i+1<<" : Enter the word "<<endl;
        cin>>s;
        words.push_back(s);
    }
    cout<<endl<<"Words present in dataset are :"<<endl;
    for(int i=0;i<n;i++)
    {
        cout<<words[i]<<endl;
    }
    t4=clock();
    SPE_PP(words);      // Encryption of each word
    t5 = clock();
    string w;
    cout<<endl;
    cout<<endl<<endl<<"=============================================="<<endl;
    cout<<"Starting the trapdoor by DU"<<endl;
    cout<<"=============================================="<<endl<<endl;
    cout<<"Enter the word to be searched"<<endl;
    cin>>w;
    t6=clock();
    Trapdoor(w,words);  //Applying trapdoor in one word
    t7 = clock();
    
    if(Test(n))     // Checking if the word is present or not 
    {
        cout<<"\nWord :"<<w <<" is found"<<endl;
    }
    else
    {
        cout<<"\nWord :"<<w <<" is not found"<<endl;
    }
    cout<<endl<<"=================================================================="<<endl;
    t8= clock();
    cout<<endl;
    cout<<"Time taken by Setup function: "<<(t2-t1)/ (CLOCKS_PER_SEC)<<endl;
    cout<<"Time taken by Key Generation function: "<<(t3-t2)/ CLOCKS_PER_SEC<<endl;
    cout<<"Time taken by SPE_PP function: "<<(t5-t4)/ CLOCKS_PER_SEC<<endl;
    cout<<"Time taken by Trapdoor function: "<<(t7-t6)/ CLOCKS_PER_SEC<<endl;
    cout<<"Time taken by Test function: "<<(t8-t7)/ CLOCKS_PER_SEC<<endl;
    cout<<endl<<"=================================================================="<<endl;

    return 0;
}
  
