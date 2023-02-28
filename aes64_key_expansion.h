#ifndef AES64_KEY_EXPANSION_H
#define AES64_KEY_EXPANSION_H

// Libraries
#include "aes64_io.h"

// Functions
/*
     Applies Column Rotation on the Given 4-Nibble Column Array
*/
void rot_word(Nibble * col){
    Nibble temp;
    temp = col[0];
    for (int i = 0; i < 3; i++)
        col[i] = col[i+1];

    col[3] = temp;
}

/*
    Applies Substitution Box on the Given 4-Nibble Column Array
    Mode - 0 -> Substitution, 1 -> Inverse Substitution
*/
void sub_word(Nibble * col){
    for (int i = 0; i < 4; i++)
        col[i] = S_BOX[col[i]];
}

/*
    Applies Round Constant XOR on the Given Nibble
*/
void r_con(Nibble * input, int round){
    //Bitwise XOR
    *input = *input ^ R_CONS[round];
}



/*
     Generates the Round Key from the given previous round key
*/
Nibble * next_round_key(const Nibble * prev_key, const int round){
    //Allocate 16-Nibble Array for New Key
    Nibble * key = (Nibble *) malloc(16);

    // Copy the Last Column of the Previous Key into a 4-Nibble Array
    Nibble * col = copy_bytes(&prev_key[12],4);

    //Applying Column Rotation on the Last Column
    rot_word(col);

    //Applying S-Box on the Last Column
    sub_word(col);

    //Applying Round Constant Operation
    r_con(&col[0], round);

    //Applying XOR of the Previous Key First Column with 4-Nibble Array
    int i = 0;
    for(;i < 4;i++)
        key[i] = col[i] ^ prev_key[i];


    //Applying XOR with Previous Key Columns
    for (i = 4; i < 16; i++)
        key[i] = key[i-4] ^ prev_key[i];

    //Free the 4-Nibble Array
    free(col);
    return key;
}

/*
     Generates the Previous Round Key from the given  round key
     round = round of the prev key
*/
Nibble * prev_round_key(const Nibble * next_key, const int round){
    int i;
    //Allocate 16-Nibble Array for New Key
    Nibble * key = (Nibble *) malloc(16);

    //Applying XOR with Previous Key Columns
    for (i = 4; i < 16; i++)
        key[i] = next_key[i-4] ^ next_key[i];
    // Copy the First Column of the Next Key into a 4-Nibble Array

    Nibble * col = copy_bytes(&key[12],4);

    //Applying Reverse Column Rotation on the Last Column
    rot_word(col);

    //Applying Inverse S-Box on the Last Column
    sub_word(col);

    //Applying Round Constant Operation
    r_con(&col[0], round);

    //Applying XOR of the Previous Key Last Column with 4-Nibble Array
    for(i = 0 ; i < 4; i++)
        key[i] = col[i] ^ next_key[i];

    //Free the 4-Nibble Array
    free(col);
    return key;
}

/*
    Returns a 10*16 Nibble Matrix Containing 10 Round Keys given the 16-Nibble Master Key
*/
Nibble ** key_expansion(Nibble * master_key){
    Nibble ** round_keys = (Nibble **)malloc(10*sizeof(Nibble *));

    // 1st Round Key
    round_keys[0] = next_round_key(master_key,0);

    // Remaining Round Keys
    for (int i = 1; i < 10; i++){
        round_keys[i] = next_round_key(round_keys[i - 1], i);
    }
    return round_keys;
}

Nibble * get_master_key(Nibble * round_key, int rounds){
    Nibble ** round_keys = (Nibble **)malloc(rounds*sizeof(Nibble *));
    Nibble * master_key;
    round_keys[rounds - 1] = prev_round_key(round_key, rounds - 1);

    // Remaining Round Keys
    for (int i = rounds - 2; i >= 0; i--){
        round_keys[i] = prev_round_key(round_keys[i + 1], i);
        free(round_keys[i + 1]);
    }
    master_key = copy_bytes(round_keys[0],16);
    free(round_keys[0]);
    free(round_keys);
    return master_key;
}


/*
    Returns a 5*16 Nibble Matrix Containing 5 Round Keys given the 16-Nibble Master Key
*/
Nibble ** round_reduced_key_expansion(const Nibble * master_key){
    Nibble ** round_keys = (Nibble**)malloc(5 * sizeof(Nibble*));

    // 1st Round Key
    round_keys[0] = next_round_key(master_key,0);

    // Remaining Round Keys
    for (int i = 1; i < 5; i++){
        round_keys[i] = next_round_key(round_keys[i - 1], i);
    }
    return round_keys;
}


/*
    Given 8-Nibble Master Key gives the 10 Round Keys in State Matrix Form
*/
void key_expansion_test(Nibble * master_key){
    printf("Master Key\n");
    print_state_matrix(master_key);
    printf("\n");

    Nibble ** keys = key_expansion(master_key);
    for(int i = 0; i < 10; i++) {
        printf("Round Key %d\n", i+1);
        print_state_matrix(keys[i]);
        printf("\n");
        free(keys[i]);
    }
    free(keys);
}

#endif