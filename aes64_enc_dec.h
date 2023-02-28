#ifndef AES64_ENC_DEC_H
#define AES64_ENC_DEC_H

//Libraries
#include "aes64_io.h"
#include "aes64_key_expansion.h"

// Utility Functions
int gcd(int a, int b)
{
    if (b == 0)
        return a;
    else
        return gcd(b, a % b);
}

void shift_row(Nibble * row, int shift) {
    //For Right Shifting
    if (shift < 0)
        shift = 4 + shift;
    int g = gcd(shift, 4);

    for (int i = 0; i < g; i++) {
        /* move i-th values of blocks */
        Nibble temp  = row[i];
        int j = i;

        while (1) {
            int k = j + shift;
            if (k >= 4)
                k = k - 4;

            if (k == i)
                break;

            row[j] = row[k];
            j = k;
        }
        row[j] = temp;
    }
}

//Operation Functions
void add_round_key(Nibble * state, const Nibble * round_key){
    for (int i = 0; i < 16; i++)
        state[i] = state[i] ^ round_key[i];
}

/*
    Applies Substitution Box on the Given 16-Nibble State Array.
    Mode - 0 -> Substitution, 1 -> Inverse Substitution
*/
void sub_bytes(Nibble * state, bool mode){
    for (int i = 0; i <16; i++)
        if(!mode)   state[i] = S_BOX[state[i]];
        else    state[i] = INV_S_BOX[state[i]];
}

/*
    Applies Shift Row Operation on the Given 16-Nibble State Array.
    Mode - 0 -> Left Shifting, 1 -> Right Shifting
*/
void shift_rows(Nibble * state, bool mode) {

    Nibble row[4];

    for (int i =0; i < 4; i++) {
        for (int j = 0; j < 4; ++j)
            row[j] = state[i + 4 * j];

        if(!mode) shift_row(row, i);
        else shift_row(row, -i);

        for (int j = 0; j < 4; ++j)
            state[i + 4 * j] = row[j];
    }

    #if defined(VERBOSE)
    printf("INVERSE SHIFT ROWS:-\n" );
    print_state_matrix(state);
    #endif

}

/*
    Applies MDS Matrix on the Given 16-Nibble State Array.
    Mode - 0 -> Mix Columns , 1 -> Inverse Mix Columns
*/
void mix_columns(Nibble * state, bool mode){

    // (Index -> MDS Mapping) 0 -> 1, 1 -> 2 , 2 -> 3
    Nibble mds_row[4] = {0x1, 0x2, 0x0, 0x0};

    // (Index -> Inverse MDS Mapping) 0 -> 9, 1 -> 11 , 2 -> 13, 3 -> 14
    Nibble inv_mds_row[4] = {0x3, 0x1, 0x2, 0x0};


    //Column Number k
    for (int k = 0; k < 4 ; k++) {
        Nibble col[4] = { [ 0 ... 3 ] = 0x00 };
        int i = 0;
        for (; i < 4; i++) {
            //Finding Sum for one Nibble in the Column
            for (int j =0; j < 4; j++) {
                if (!mode)
                    col[i] ^= MIX_COLUMNS[mds_row[j]][state[4 * k + j]];
                else
                    col[i] ^= INV_MIX_COLUMNS[inv_mds_row[j]][state[4 * k + j]];
            }

            // Right Rotating the MDS Row
            if(!mode) shift_row(mds_row, -1);
            else shift_row(inv_mds_row, -1);
        }
        // Assigning Mixed Column to State Array Column
        for (i=0; i < 4; i++)
            state[4 * k + i] = col[i];
    }
}


//Encryption Functions
Nibble * round_aes_enc(Nibble *prev_state, const Nibble *round_key, const int round, const int final_round){
    Nibble * round_state = copy_bytes(prev_state, 16);

    sub_bytes(round_state, 0);
    shift_rows(round_state, 0);
    if(round != final_round-1)  mix_columns(round_state, 0);
    add_round_key(round_state,round_key);

    return round_state;
}

/*
    Given 16-Nibble Plaintext and Master Key gives the 10 Round of AES Encryption, returns AES Encrypted Round States
*/
Nibble ** aes_enc(Nibble * plaintext, Nibble * master_key, int final_round){
    Nibble ** round_states = (Nibble**)malloc(10 * sizeof(Nibble*));
    Nibble * plaintext_temp = copy_bytes(plaintext, 16);
    // Pre-Whitening -  Master Key XOR with Plaintext
    add_round_key(plaintext_temp, master_key);

    //Key Expansion to get Round Keys
    Nibble ** round_keys = key_expansion(master_key);

    // 1st Round
    round_states[0] = round_aes_enc(plaintext_temp, round_keys[0], 0, final_round);
    for (int i = 1; i < 10; i++) {
        round_states[i] = round_aes_enc(round_states[i-1], round_keys[i], i, final_round);
        free(round_keys[i]);
    }
    free(round_keys[0]);
    free(round_keys);
    free(plaintext_temp);
    return round_states;
}

Nibble * aes_enc_ciphertext(Nibble * plaintext, Nibble * master_key, int final_round){
    Nibble ** round_states = aes_enc(plaintext, master_key, final_round);
    Nibble * ciphertext = copy_bytes(round_states[9], 16);
    for(int i = 0; i < 10; i++) free(round_states[i]);
    free(round_states);
    return ciphertext;
}

/*
       Given 8-Nibble Plaintext and Master Key gives the 10 Round of AES Encryption in State Matrix Form
       Also returns the 8-Nibble Ciphertext after 10 Round Encryption
*/
Nibble * aes_enc_test(Nibble * plaintext, Nibble * master_key, bool verbose){
    if(verbose){
        printf("Expanded Master Key\n");
        print_state_matrix(master_key);
        printf("\n");
        printf("Expanded Plaintext\n");
        print_state_matrix(plaintext);
        printf("\n");
    }

    Nibble ** round_states = aes_enc(plaintext, master_key, 10);

    // Store Ciphertext
    Nibble * ciphertext = copy_bytes(round_states[9], 16);

    for(int i = 0; i < 10; i++) {
        if(verbose){
            printf("Round State %d\n", i+1);
            print_state_matrix(round_states[i]);
            printf("\n");
        }
        free(round_states[i]);
    }

    free(round_states);
    return ciphertext;
}

// Decryption Functions
Nibble * round_aes_dec(Nibble *prev_state, const Nibble *round_key, const int round){
    Nibble * round_state = copy_bytes(prev_state, 16);
    add_round_key(round_state,round_key);
    if(round != 9)  mix_columns(round_state, 1);
    shift_rows(round_state, 1);
    sub_bytes(round_state, 1);

    return round_state;
}

/*
    Given 16-Nibble Ciphertext and Master Key gives the 10 Round of AES Encryption, returns AES Encrypted Round States
*/
Nibble ** aes_dec(Nibble * ciphertext, Nibble * master_key){

    Nibble ** round_states = (Nibble**)malloc(10 * sizeof(Nibble*));

    //Key Expansion to get Round Keys
    Nibble ** round_keys = key_expansion(master_key);

    // Undoing Last Round
    round_states[9] = round_aes_dec(ciphertext, round_keys[9], 9);
    for (int i = 8; i >= 0; i--) {
        round_states[i] = round_aes_dec(round_states[i+1], round_keys[i], i);
        free(round_keys[i+1]);
    }
    free(round_keys[9]);
    free(round_keys);
    // Undo Pre-Whitening - Master Key XOR with Ciphertext
    add_round_key(round_states[0], master_key);
    return round_states;
}

/*
    Given 8-Nibble Ciphertext and Master Key gives the 10 Round of AES Encryption in State Matrix Form
    Also returns the 8-Nibble Plaintext after 10 Round Decryption
*/
Nibble * aes_dec_test(Nibble * ciphertext, Nibble * master_key, bool verbose){
    if(verbose){
        printf("Expanded Master Key\n");
        print_state_matrix(master_key);
        printf("\n");
        printf("Expanded Ciphertext\n");
        print_state_matrix(ciphertext);
        printf("\n");
    }


    Nibble ** round_states = aes_dec(ciphertext, master_key);

    // Store and Reduce Plaintext
    Nibble * plaintext = copy_bytes(round_states[0], 16);

    for(int i = 9; i >= 0; i--) {
        if(verbose){
            printf("Round State %d\n", i+1);
            print_state_matrix(round_states[i]);
            printf("\n");
        }
        free(round_states[i]);

    }
    free(round_states);

    return plaintext;
}

#endif
