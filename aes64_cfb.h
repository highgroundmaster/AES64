#ifndef AES64_CFB_H
#define AES64_CFB_H

//Libraries
#include "aes64_io.h"
#include "aes64_key_expansion.h"
#include "aes64_enc_dec.h"

Nibble * generate_iv(Nibble * master_key){
    Nibble hex_seed[17];

    printf("Enter the IV seed Block in 16 Character Hexadecimal Stream form:\n");
    fgets((char*)hex_seed, sizeof(hex_seed), stdin);
    Nibble * iv_seed = hex_string_to_state((char*)hex_seed);
    Nibble * iv  = aes_enc_ciphertext(iv_seed,master_key, 10);

    int c;
    while ((c = getchar()) != EOF && c != '\n' );
    free(iv_seed);
    return iv;
}

Nibble ** get_plaintext_stream(){
    Nibble hex_string[17];
    int count = 0;
    Nibble ** plaintext_stream = (Nibble**)malloc(sizeof(Nibble*));

    printf("Enter the Plaintext State Blocks in 16 Character Hexadecimal Stream form:\n");
    while(fgets((char*)hex_string, sizeof(hex_string), stdin)){
        plaintext_stream = (Nibble **)realloc(plaintext_stream,(count + 2)*sizeof(Nibble*));

        plaintext_stream[count + 1] = hex_string_to_state((char*)hex_string);
        count++;
        int c;
        while ((c = getchar()) != EOF && c != '\n' );
    }
    plaintext_stream[0] = int_to_nibbles(count, 4);
    return plaintext_stream;
}

Nibble ** cfb_enc(Nibble ** plaintext_stream, Nibble * master_key, Nibble * iv){
    int count = nibbles_to_int(plaintext_stream[0],4);
    Nibble ** ciphertext_stream = (Nibble**)malloc((count + 1)*sizeof(Nibble*));

    ciphertext_stream[0] = int_to_nibbles(count , 4);

    //Initial IV Encryption
    ciphertext_stream[1] = aes_enc_ciphertext(iv, master_key, 10);

    int i;
    //XOR With Plaintext
    for(i = 0; i < 16; i++)
        ciphertext_stream[1][i] ^= plaintext_stream[1][i];

    //Rest of the Blocks
    for (i = 2; i <= count ; i++) {
        ciphertext_stream[i] = aes_enc_ciphertext(ciphertext_stream[i-1], master_key, 10);
        for(int j = 0; j < 16; j++)
            ciphertext_stream[i][j] ^= plaintext_stream[i][j];
    }

    return ciphertext_stream;
}

Nibble ** cfb_dec(Nibble ** ciphertext_stream, Nibble * master_key, Nibble * iv){
    int count = nibbles_to_int(ciphertext_stream[0],4);
    Nibble ** plaintext_stream = (Nibble**)malloc((count + 1)*sizeof(Nibble*));

    plaintext_stream[0] = int_to_nibbles(count , 4);

    //Initial IV Encryption
    plaintext_stream[1] = aes_enc_ciphertext(iv, master_key, 10);
    int i;
    //XOR With Ciphertext
    for(i = 0; i < 16; i++)
        plaintext_stream[1][i] ^= ciphertext_stream[1][i];

    //Rest of the Blocks
    for (i = 2; i <= count ; i++) {
        plaintext_stream[i] = aes_enc_ciphertext(ciphertext_stream[i-1], master_key, 10);
        for(int j = 0; j < 16; j++)
            plaintext_stream[i][j] ^= ciphertext_stream[i][j];
    }

    return plaintext_stream;
}


void cfb_test(bool verbose, bool is_error){
    int i;
    printf("Enter the Master Key Block in 16 Character Hexadecimal Stream form:\n");
    Nibble * master_key = scan_state();

    if(verbose){
        printf("Master Key for Encryption Black Box - AES64\n");
        print_state_matrix(master_key);
    }

    Nibble * iv= generate_iv(master_key);
    if(verbose){
        printf("Initialization Vector\n");
        print_state_matrix(iv);
    }

    Nibble ** plaintext_stream = get_plaintext_stream();
    int count = nibbles_to_int(plaintext_stream[0],4);



    Nibble ** ciphertext_stream = cfb_enc(plaintext_stream, master_key, iv);
    if(is_error){
        printf("Flipping LSB Bit of First Nibble in First Ciphertext Block\n");
        int flip = (ciphertext_stream[1][0]%2 == 0) ? 1 : -1;
        ciphertext_stream[1][0] += flip;
    }
    Nibble ** decrypted_plaintext_stream = cfb_dec(ciphertext_stream, master_key, iv);

    free(master_key);
    free(iv);

    free(ciphertext_stream[0]);
    free(plaintext_stream[0]);
    free(decrypted_plaintext_stream[0]);

    printf("\nPlaintext Blocks\n");
    for(i = 1; i <= count; i++){
        for(int j =0 ; j < 16; j++)
            printf("%01x",plaintext_stream[i][j]);
        printf("\n");
    }

    printf("\nCiphertext Blocks\n");
    for(i = 1; i <= count; i++){
        for(int j =0 ; j < 16; j++)
            printf("%01x",plaintext_stream[i][j]);
        printf("\n");
    }

    printf("\nDecrypted Plaintext Blocks\n");
    for(i = 1; i <= count; i++){
        for(int j =0 ; j < 16; j++)
            printf("%01x",decrypted_plaintext_stream[i][j]);
        printf("\n");
    }
    printf("\n");

    if(verbose){
        for (i = 1; i <= count ; i++) {

            printf("Plaintext Block %d\n", i);
            print_state_matrix(plaintext_stream[i]);

            printf("Ciphertext Block %d\n", i);
            print_state_matrix(ciphertext_stream[i]);

            printf("Decrypted Plaintext Block %d\n", i);
            print_state_matrix(decrypted_plaintext_stream[i]);

            free(ciphertext_stream[i]);
            free(plaintext_stream[i]);
            free(decrypted_plaintext_stream[i]);
        }
    }

    free(ciphertext_stream);
    free(plaintext_stream);
    free(decrypted_plaintext_stream);

}



#endif
