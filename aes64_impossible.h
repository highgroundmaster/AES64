
#ifndef AES64_IMPOSSIBLE_H
#define AES64_IMPOSSIBLE_H

#include <stdbool.h>
#include "aes64_io.h"
#include "aes64_key_expansion.h"
#include "aes64_enc_dec.h"

Nibble * generate_diagonal_indexes(const int diagonal){
    Nibble * indexes = (Nibble *)malloc(4);
    indexes[0] = (Nibble) diagonal;
    for (int i = 1; i < 4; i++) {
        indexes[i] = 5 + indexes[i-1];
        if((indexes[i] != 0) && (indexes[i] % 4 == 0))  indexes[i] -= 4;
    }
    return indexes;
}

/*
    Generates the Lookup-Table of 4 bytes of S^SB_1 from the S^MC_1
 */
Nibble ** generate_lut(const int diagonal){
    Nibble * indexes = generate_diagonal_indexes(diagonal);
    Nibble ** lut = (Nibble **) malloc(15 * sizeof(Nibble *));
    Nibble MC_state[16] = {[0 ... 15] = 0};
    for (Nibble i = 1; i < 16; i++) {
        // Invert Till Shift Rows - S^SB_1
        // Convert the Diagonal Value to Column Number
        MC_state[((4 - diagonal) % 4) * 4] =  i;
        Nibble * SB_state = copy_bytes(MC_state, 16);
        mix_columns(SB_state, 1);
        shift_rows(SB_state, 1);
        lut[i-1] = (Nibble *)malloc(4);
        for (int j = 0; j < 4; j++)
            lut[i-1][j] = SB_state[indexes[j]];
        free(SB_state);
    }
    free(indexes);
    return lut;
}

/*
    Provide a 14-Nibble Array of Constant Cell Values to be stored in the State Matrices,
    Indices [0,5,10,15] -> All Cells will be generated and stored
    Returns 2^16 Plaintext Structure Set given the Constant Value for CONSTANT Cells
*/
Nibble ** generate_structure(const Nibble* constants, const int diagonal){
    Nibble * indexes = generate_diagonal_indexes(diagonal);
    Nibble ** structure = (Nibble**)malloc(pow(2,16) * sizeof(Nibble*));

    for (int all = 0; all < pow(2,16); all++) {
        Nibble * all_values = int_to_nibbles(all, 4);
        structure[all] = (Nibble *) malloc(16);
        int count = 0;

        // Constant Cells
        for (int i = 0; i < 12; i++){
            while ((count < 4) && (i + count == indexes[count]))
                count++;
            structure[all][i + count] = constants[i];
        }

        // All Cells
        for (int i = 0; i < 4; i++)
            structure[all][indexes[i]] = all_values[i] ;
        free(all_values);
    }
    free(indexes);
    return structure;
}

/*
    Given 16-Nibble Plaintext and Master Key gives the 5 Round States of AES Encryption
*/
Nibble * aes_enc_5(const Nibble * plaintext, const Nibble * master_key){
    Nibble * ciphertext = copy_bytes(plaintext, 16);
    // Pre-Whitening -  Master Key XOR with Plaintext
    add_round_key(ciphertext, master_key);

    //Key Expansion to get Round Keys
    Nibble ** round_keys = round_reduced_key_expansion(master_key);

    for (int i = 0; i < 5; i++) {
        ciphertext = round_aes_enc(ciphertext, round_keys[i], i, 5);
        free(round_keys[i]);
    }

    free(round_keys);
    return ciphertext;
}

bool check_conforming(const Nibble * ciphertext1, const Nibble * ciphertext2){
    int indexes[4] = {0, 7, 10, 13};
    for (int i = 0; i < 4; i++)
        if (ciphertext1[indexes[i]] != ciphertext2[indexes[i]]) return false;
    return true;
}

Nibble ** get_conforming_pairs(Nibble ** structure, Nibble ** ciphertexts, const int diagonal){
    Nibble ** conforming_pairs = (Nibble **)malloc(sizeof(Nibble *));
    int count = 0;
    Nibble * indexes = generate_diagonal_indexes(diagonal);
    char label[100];
    for (int i = 0; i < pow(2, 16); i++) {
        sprintf(label, "%d Conforming Pairs : %d Plaintext Pairs", count, i);
        print_progress(100 * i / pow(2, 16), label);

        for (int j = i + 1; j < pow(2, 16); j++) {
           // If Conforming, add (Plaintext, Ciphertext) Pair to the 2d Array
           if (check_conforming(ciphertexts[i], ciphertexts[j])){
               count++;
               conforming_pairs = (Nibble **) realloc(conforming_pairs, (count + 1) * sizeof(Nibble*));
               conforming_pairs[count] = (Nibble *) malloc(8);
               for(int k = 0; k < 4; k++){
                   conforming_pairs[count][k] = structure[i][indexes[k]];
                   conforming_pairs[count][k + 4] = structure[j][indexes[k]];
               }
           }
        }
    }
    conforming_pairs[0] = int_to_nibbles(count, 16);
    free(indexes);
    printf("\n");
    return conforming_pairs;
}

Nibble * find_solutions(const Nibble input_diff,const Nibble output_diff){
    Nibble * inputs = (Nibble *)calloc(1, sizeof(Nibble));
    Nibble count = 0;

    for (Nibble input = 0; input < 16; input++) {
        if (input_diff > 0 && output_diff > 0 && (S_BOX[input] ^ S_BOX[input ^ input_diff]) == output_diff){
            count++;
            inputs = (Nibble *) realloc(inputs, (count + 1) * sizeof(Nibble));
            inputs[count] = input;
        }
    }
    inputs[0] = count;
    return inputs;
}

Nibble ** combination(Nibble ** row_solutions){
    int count = 0;
    Nibble ** combinations = (Nibble**) malloc(sizeof(Nibble *));
    Nibble size1 = row_solutions[0][0];
    Nibble size2 = row_solutions[1][0];
    Nibble size3 = row_solutions[2][0];
    Nibble size4 = row_solutions[3][0];
    for (Nibble i = 1; i <= size1; i++) {
        for (Nibble j = 1; j <= size2; j++) {
            for (Nibble k = 1; k <= size3; k++) {
                for (Nibble x = 1; x <= size4; x++) {
                    count++;
                    combinations = (Nibble **) realloc(combinations, (count + 1) * sizeof(Nibble *));
                    combinations[count] = (Nibble *) malloc(4);
                    combinations[count][0] = row_solutions[0][i];
                    combinations[count][1] = row_solutions[1][j];
                    combinations[count][2] = row_solutions[2][k];
                    combinations[count][3] = row_solutions[3][x];
                }
            }
        }
    }
    combinations[0] = int_to_nibbles(count, 5);
    return combinations;

}


Nibble * recovery(Nibble ** conforming_pairs, const int diagonal){
    Nibble * counter = (Nibble *) calloc(pow(2, 13), sizeof(Nibble));
    char label[100];
    int sol_count = 0;
    Nibble ** lut = generate_lut(diagonal);
    int num_pairs = nibbles_to_int(conforming_pairs[0], 16);
    int pair_index = 1;
    printf("\nGenerating Wrong Key Suggestions\n");
    for (; pair_index <= num_pairs; pair_index++) {

        Nibble * plaintext_diff = (Nibble *) malloc(4);
        Nibble * sub_key = (Nibble *) malloc(8);

        // Fixed Plaintext Difference
        for (int i = 0; i < 4; i++)
            plaintext_diff[i] = conforming_pairs[pair_index][i] ^ conforming_pairs[pair_index][i + 4];


        // Check Solutions
        for (int lut_index = 0; lut_index < 15; lut_index++) {
            Nibble ** row_solutions = (Nibble **) malloc(4 * sizeof(Nibble *));
            for (int i = 0; i < 4; i++)
                row_solutions[i] = find_solutions(plaintext_diff[i], lut[lut_index][i]);

            // If there are solutions for an LuT Row, do different combinations
            if(row_solutions[0][0] && row_solutions[1][0] && row_solutions[2][0] && row_solutions[3][0]){
                Nibble** combinations = combination(row_solutions);
                int num_comb = nibbles_to_int(combinations[0], 5);
                free(combinations[0]);
                for (int comb_index = 1; comb_index <= num_comb; comb_index++) {
                    for (int i = 0; i < 4; i++) {
                        // Sub key Recovery - two keys from two plaintexts
                        sub_key[i] = conforming_pairs[pair_index][i] ^ combinations[comb_index][i];
                        sub_key[i + 4] = conforming_pairs[pair_index][i + 4] ^ combinations[comb_index][i];
                    }
                    free(combinations[comb_index]);
                    // If already not counted
                    if(!get_bit(counter, nibbles_to_int(sub_key, 4))){
                        set_bit(counter, nibbles_to_int(sub_key, 4));
                        sol_count++;
                    }

                    // If already not counted
                    if(!get_bit(counter, nibbles_to_int(&sub_key[4], 4))){
                        set_bit(counter, nibbles_to_int(&sub_key[4], 4));
                        sol_count++;
                    }


                    if (sol_count == pow(2, 16) - 1)
                        break;

                }
                free(combinations);
            }

            for (int i = 0; i < 4; i++)
                free(row_solutions[i]);

            free(row_solutions);

            if (sol_count == pow(2, 16) - 1)
                break;
        }

        free(sub_key);
        free(plaintext_diff);

        sprintf(label, "%d Wrong Key Suggestions : %d Conforming Pairs", sol_count, pair_index);

        print_progress(100 * pair_index / num_pairs, label);

        if (sol_count == pow(2, 16) - 1)
            break;

    }
    printf("\n\nStatistics\n");
    printf("\t%f Wrong Key Suggestions per Conforming Pair Generated\n", sol_count / (float) pair_index);
    printf("\t%f Wrong Key Suggestions per Look-up Table Row Generated for Fixed Pair", sol_count / (float) (pair_index * 15));
    for (int lut_index = 0; lut_index < 15; lut_index++)
        free(lut[lut_index]);
    free(lut);
    printf("\n");

    return counter;
}

#endif
