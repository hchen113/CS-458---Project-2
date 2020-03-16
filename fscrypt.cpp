#include "fscrypt.hpp"
#include <string>
#include <vector>
#include <cstring>

using namespace std;

// encrypt plaintext of length bufsize. Use keystr as the key.
void *fs_encrypt(void *plaintext, int bufsize, char *keystr, int *resultlen){
    //cout << "BEGINNING ENCRYPTION.\n";
    
    //cout << "CREATING BLOCKFISH KEY.\n";
    BF_KEY key;
    BF_set_key(&key, BLOCKSIZE * 2, (unsigned char *)keystr);
    
    //cout << "CREATING PLAINTEXT VECTOR.\n";
    vector<unsigned char> ptxt;
    unsigned char * pointer = (unsigned char *) plaintext;
    for(int i = 0; i < bufsize; i++){
        ptxt.push_back(*pointer);
        pointer ++;
    }
    
    //cout << "CREATING XOR VECTOR. \n";
    vector<unsigned char> XOR;
    int XOR_counter = 0;
    
   // cout << "CREATING INITILIZATION VECTOR.\n";
    vector<unsigned char> ivec;
    for(int i = 0; i < BLOCKSIZE; i++){
        ivec.push_back('0');
    }
    
    //cout << "BEGINNERING XOR OF FIRST [BLOCKSIZE] OF CHAR WITH IVEC VECTOR. \n";
    for (int i = 0; i < BLOCKSIZE; i++){
        //cout << "XOR-ING " << ptxt[0] << " OF PLAINTEXT. \n";
        XOR.push_back(ptxt[0] ^ ivec[i]);
        XOR_counter ++;
        ptxt.erase(ptxt.begin());
    }
    
    //cout << "BEGINNERING ECNRYPTION OF FIRST [BLOCKSIZE] OF CHAR, PLACING IN CIPHERTEXT BUFFER. \n";
    unsigned char * buffer = (unsigned char *)calloc(bufsize, sizeof(char));
    BF_ecb_encrypt((unsigned char *)XOR.data(),(unsigned char *) buffer, &key, BF_ENCRYPT);
    
    //cout << "BEGINNERING ECNRYPTION OF THE REST OF PLAINTEXT, PLACING IN CIPHERTEXT BUFFER. \n";
    unsigned char * buffer_pointer = buffer;
    
    while (ptxt.size() > 0){
        if(ptxt.size() < BLOCKSIZE){
            while (ptxt.size() < BLOCKSIZE){
                ptxt.push_back(0);
            }
        }
        
        for (int i = 0; i < BLOCKSIZE; i++){
            //cout << (ptxt[0] ^ *buffer) << "\n";
            XOR.push_back(ptxt[0] ^ *buffer);
            buffer ++;
            ptxt.erase(ptxt.begin());
            
        }
        //cout << "BEGINNERING ECNRYPTION OF XOR VECTOR, PLACING IN CIPHERTEXT VECTOR. \n";
        BF_ecb_encrypt((unsigned char *)XOR.data() + XOR_counter,(unsigned char *) buffer, &key, BF_ENCRYPT);
    }
    *resultlen = (int) strlen((char*)buffer_pointer);
    //cout << "\n\n.";
    return (void *) buffer_pointer;
}


void *fs_decrypt(void *ciphertext, int bufsize, char *keystr, int *resultlen){
    
    //cout << "\n\nBEGINNING DECRYPTION.\n";
    
    //cout << "CREATING BLOCKFISH KEY.\n";
    BF_KEY key;
    BF_set_key(&key, BLOCKSIZE * 2, (unsigned char *)keystr);
    
    
    //cout << "CREATING INITILIZATION VECTOR.\n";
    vector<unsigned char> ivec;
    for(int i = 0; i < BLOCKSIZE; i++){
        ivec.push_back('0');
    }
    
    //cout << "CREATING PLAINTEXT BUFFER. \n";
    unsigned char * ptxt =(unsigned char *)calloc(bufsize + 10, sizeof(char));
    unsigned char * ret_ptxt = ptxt;
    int ptxt_counter = BLOCKSIZE;
    //cout << "CREATING POINTER TO DECRYPTION BUFFER. \n";
    unsigned char * buffer = (unsigned char *)calloc(bufsize + 10, sizeof(char));
    
    //cout << "CREATING POINTER TO CIPHER TEXT AND XOR_CIPHER. \n";
    unsigned char * cipher = (unsigned char *)ciphertext;
    unsigned char * XOR_cipher = cipher;

    //cout << "BEGINNERING DECRYPTION OF FIRST [BLOCKSIZE] OF CIPHERTEXT, PLACING IN BUFFER. \n";
    BF_ecb_encrypt((unsigned char *) cipher,(unsigned char *) buffer, &key, BF_DECRYPT);

    //cout << "BEGINNERING XOR OF FIRST [BLOCKSIZE] OF DECRYPTED CIPHERTEXT WITH IVEC VECTOR. \n";
    for (int i = 0; i < BLOCKSIZE; i++)
    {
        //cout << (*XOR_cipher ^ *buffer) << "\n";
        ptxt[i] = ivec[i] ^ *buffer;
        buffer ++;
        cipher ++;
    }

    
    //cout << "BEGINNERING DECRYPTION OF THE REST OF CIPHERTEXT, PLACING IN PLAINTEXT BUFFER. \n";
    bufsize = bufsize - BLOCKSIZE;
    while (bufsize > 0)
    {
        BF_ecb_encrypt((unsigned char *) cipher,(unsigned char *) buffer, &key, BF_DECRYPT);
        
        for (int i = 0; i < BLOCKSIZE; i++)
        {
            //cout << (*XOR_cipher ^ *buffer) << "\n";
            ptxt[ptxt_counter] = (*XOR_cipher ^ *buffer);
            buffer ++;
            cipher ++;
            XOR_cipher ++;
            ptxt_counter ++;
        }
        bufsize = bufsize - BLOCKSIZE;
    }

    
    //cout << "\n\n";
    *resultlen = (int) strlen((const char *)ret_ptxt) + 1;
    return (void *) ret_ptxt;
}





// THIS ASSIGNMENT REFERENCED: https://github.com/ZeldaZach/CS458/tree/master/p2-zhalper3
