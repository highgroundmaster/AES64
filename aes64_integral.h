#ifndef AES64_INTEGRAL_H
#define AES64_INTEGRAL_H

#include <stdbool.h>
#include "aes64_io.h"
#include "aes64_key_expansion.h"
#include "aes64_enc_dec.h"

/*
    Provide a 16-Nibble Array of values to be stored in the State Matrices,
    -1 -> Where the all index is present
    Returns 16 Plaintext Delta Set Given the Constant Value for CONSTANT Cells and the index for ALL Property Cell
*/
Nibble ** get_delta_set(const Nibble * values){
    //Allocate Space for 16 Plaintext Delta Set
    Nibble ** delta_set = (Nibble**)malloc(16 * sizeof(Nibble*));
    int all_index;

    for (Nibble i = 0x0; i <= 0xf; i++){
        delta_set[i] = (Nibble *) malloc(16);

        for(Nibble j = 0x0; j <= 0xf; j++){
            delta_set[i][j] = values[j];
            if(values[j] == -1)   all_index = j;
        }

        delta_set[i][all_index] = i;
    }
    return delta_set;
}

Nibble **get_delta_set_hex(){
    Nibble ** delta_set = (Nibble**)malloc(16 * sizeof(Nibble*));
    for(int i = 0; i < 16; i++)
        delta_set[i] = scan_state();
    return delta_set;
}

bool check_all_property(const Nibble * cells){
    int count[16] = {[0 ... 15] = 0};
    // Put all array elements in a map of count
    for (int i = 0; i < 16; i++) {
        //If count greater than 0 that means it's not unique
        if (count[cells[i]])    return false;
        count[cells[i]]++;
    }
    return true;
}

bool check_constant_property(const Nibble * cells){
    Nibble constant = cells[0];
    for (int i=1; i < 16; i++){
        if (cells[i] != constant)   return false;
    }
    return true;
}

bool check_balance_property(const Nibble * cells){
    Nibble xor = 0x00;
    for(int i = 0; i < 16; i++)
        xor ^= cells[i];
    return !xor;
}

/*
    Prints Integral Property Matrix of a Delta Set
    'A' - ALL Property Cell
    'C' - CONSTANT Property Cell
    'B' - BALANCE Property Cell
    'X' - NONE Property Cell
*/
void print_integral_property(Nibble ** delta_set){
    Nibble * cells = (Nibble *) malloc(16);
        for(int i = 0; i < 4; i++){
            for(int j = 0; j < 4; j++){
                //Cells in Row Major, Delta Set in Row Major
                for(int index = 0; index < 16; index ++)
                    cells[index] = delta_set[index][i + 4 * j];

                if(check_all_property(cells))   printf("A ");
                else if (check_constant_property(cells))    printf("C ");
                else if(check_balance_property(cells))    printf("B ");
                else printf("X ");
            }
            printf("\n");
    }
    printf("\n");
    free(cells);
}

/*
    - One Round of Round reduced AES encryption of all the 16 States from Delta Set
    - Verbose -> 1 Prints State Matrix for every Operation - Useful for Integral Property Analysis
*/
void round_aes_enc_5(Nibble ** delta_set, const Nibble *round_key, const int round, const bool verbose){
    int i = 0;

    //SUB_BYTES
    for(; i < 16; i++){

        sub_bytes(delta_set[i], 0);
        if (verbose) {
            printf("ROUND %d PLAINTEXT %d - SUB BYTES \n", round + 1, i + 1);
            print_state_matrix(delta_set[i]);
        }
    }
    printf("ROUND %d - SUB BYTES\n", round + 1);
    print_integral_property(delta_set);

    // SHIFT ROWS
    for(i=0; i < 16; i++){

        shift_rows(delta_set[i], 0);
        if (verbose) {
            printf("ROUND %d PLAINTEXT %d - SHIFT ROWS \n", round + 1, i + 1);
            print_state_matrix(delta_set[i]);
        }
    }
    printf("ROUND %d - SHIFT ROWS\n", round + 1);
    print_integral_property(delta_set);

    // MIX COLUMNS
    if(round != 4){
        for(i=0; i < 16; i++){
            mix_columns(delta_set[i], 0);
            if (verbose) {
                printf("ROUND %d PLAINTEXT %d - MIX COLUMNS \n", round + 1, i + 1);
                print_state_matrix(delta_set[i]);
            }
        }
        printf("ROUND %d - MIX COLUMNS\n", round + 1);
        print_integral_property(delta_set);
    }

    // ADD ROUND KEY
    for(i=0; i < 16; i++){
        add_round_key(delta_set[i], round_key);
        if (verbose) {
            printf("ROUND %d PLAINTEXT %d - ADD ROUND KEY \n", round + 1, i + 1);
            print_state_matrix(delta_set[i]);
        }
    }
    printf("ROUND %d - ADD ROUND KEY\n", round + 1);
    print_integral_property(delta_set);
}

/*
    Given 16-Nibble Plaintext and Master Key gives the 5 Round of AES Encryption
    Prints Integral Property Matrix
    Verbose -> 1 Prints State Matrix for every Operation - Useful for Integral Property Analysis
*/
void aes_delta_enc_5(Nibble ** delta_set, Nibble * master_key, const bool verbose){
    int i;
    //Plaintext
    if(verbose){
        for(i = 0 ;i < 16; i++){
            printf("PLAINTEXT %d \n", i + 1);
            print_state_matrix(delta_set[i]);
        }
    }
    printf("PLAINTEXT DELTA SET\n");
    print_integral_property(delta_set);
    // Pre-Whitening - Master key XOR with Plaintext
    for(i = 0; i < 16; i++){
        add_round_key(delta_set[i], master_key);
        if (verbose) {
            printf("PLAINTEXT %d - PRE-WHITENING \n", i + 1);
            print_state_matrix(delta_set[i]);
        }
    }
    printf("PRE-WHITENING\n");
    print_integral_property(delta_set);

    //Key Expansion to get Round Keys
    Nibble ** round_keys = round_reduced_key_expansion(master_key);

    for (i =0; i < 5; i++) {
        round_aes_enc_5(delta_set, round_keys[i], i, verbose);
        free(round_keys[i]);
    }
    free(round_keys);
}

Nibble * get_partial_state(const Nibble * state, const int col_num){
    Nibble * partial_state = (Nibble *) malloc(4);

    for(int j = 0; j < 4; j++){
        // Shift Row Operation
        int index = 4*col_num -3*j;
        if (index < 0)  index += 16;
        partial_state[j]= state[index];
    }
    return partial_state;
}

/*
 Returns the Partial Diagonal 4 Nibbles from the Ciphertexts in Delta Set for integral analysis
 */
Nibble ** get_partial_delta_set(Nibble ** delta_set, const int col_num){
    Nibble ** partial_delta_set = (Nibble**)malloc(16 * sizeof(Nibble*));

    for (int i = 0; i < 16; i++)
        partial_delta_set[i] = get_partial_state(delta_set[i], col_num);
    return partial_delta_set;
}

Nibble ** reverse_2_rounds(Nibble ** partial_delta_set, const Nibble * partial_round_5, const Nibble * partial_round_4){

    int i = 0;
    //Undo Round 5 Add Round Key
    //Partial XOR with Round 5 Guess and Ciphertext
    for(; i < 16; i++){
        for (int j = 0; j < 4; j++)
            partial_delta_set[i][j] ^= partial_round_5[j];
    }

    //Shift Rows not required as we are not doing in state matrix form

    //Undo Round 5 Sub Bytes Partial Inverse Sub Bytes
    for(i = 0; i < 16; i++){
        for (int j = 0; j < 4; j++)
            partial_delta_set[i][j] = INV_S_BOX[partial_delta_set[i][j]];
    }

    //Undo Round 4 Add Round Key
    //Partial XOR with Round 4 Guess and Ciphertext
    for(i = 0; i < 16; i++){
        for (int j = 0; j < 4; j++)
            partial_delta_set[i][j] ^= partial_round_4[j];
    }
    //Undo Round 4 Mix Column
    //Partial Mix Column
    // (Index -> Inverse MDS Mapping) 0 -> 9, 1 -> 11 , 2 -> 13, 3 -> 14
    Nibble inv_mds_row[4] = {0x3, 0x1, 0x2, 0x0};
    for(i = 0; i < 16; i++){
        Nibble col[4] = { [ 0 ... 3 ] = 0x00 };
        int j = 0;
        for (; j < 4; j++) {
            //Finding Sum for one Nibble in the Column
            for (int k =0; k < 4; k++)
                col[j] ^= INV_MIX_COLUMNS[inv_mds_row[k]][partial_delta_set[i][k]];

            // Right Rotating the Inverse MDS Row
            shift_row(inv_mds_row, -1);
        }
        // Assigning Mixed Column to State Array Column
        for (j = 0; j < 4; j++)
            partial_delta_set[i][j] = col[j];
    }

    //Undo Round 4 Sub Bytes Partial Inverse Sub Bytes
    for(i = 0; i < 16; i++){
        for (int j = 0; j < 4; j++)
            partial_delta_set[i][j] = INV_S_BOX[partial_delta_set[i][j]];
    }
}

bool is_partial_balanced(Nibble ** const partial_delta_set){
    // Check Balance Property for Partial Delta Set
    Nibble * cells =  (Nibble *) malloc(16);
    bool is_balanced = 1;
    for(int j = 0; j < 4; j++){
        for( int k = 0; k < 16; k++)
            cells[k] = partial_delta_set[k][j];
        is_balanced &= check_balance_property(cells);
    }
    free(cells);
    return is_balanced;
}

/*
    Returns the 16 Nibble master key  from the Ciphertext Delta Set after doing the attack
*/
Nibble ** integral_attack_1(Nibble ** delta_set, int col_num){
    Nibble ** possible_round_keys = (Nibble**)malloc(sizeof(Nibble*));
    int i, count = 0;
    Nibble ** partial_delta_set;

    double amount = 0, change = 100/pow(2, 16);
    char label[30];
    for(i = 0; i < pow(2, 16) ; i++){
        //Printing Progress Bar
        amount += change;
        sprintf(label, "INTEGRAL ATTACK - COLUMN %d", col_num);
        print_progress(amount, label);

        Nibble * partial_round_5 = int_to_nibbles(i, 4);
        for(int l = 0; l < pow(2, 16); l++){
            partial_delta_set = get_partial_delta_set(delta_set, col_num);
            Nibble * partial_round_4 = int_to_nibbles(l, 4);
            int j;
            // Reverse Last 2 Rounds
            reverse_2_rounds(partial_delta_set, partial_round_5, partial_round_4);

            // Check Balance Property for Partial Delta Set
            if (is_partial_balanced(partial_delta_set)){
                count++;
                possible_round_keys = (Nibble **) realloc(possible_round_keys, (count + 1) * sizeof(Nibble*));
                possible_round_keys[count] = (Nibble *) malloc(8);

                for(j = 0; j < 4; j ++){
                    possible_round_keys[count][j] = partial_round_4[j];
                    possible_round_keys[count][4 + j] = partial_round_5[j];
                }
            }

            free(partial_round_4);

            for(j = 0; j < 16; j++)
                free(partial_delta_set[j]);

            free(partial_delta_set);
        }
        free(partial_round_5);
    }

    possible_round_keys[0] = int_to_nibbles(count, 8);
    return possible_round_keys;
}

Nibble ** integral_attack_2(Nibble ** delta_set, Nibble ** possible_keys, int col_num){
    Nibble  * partial_round_4, * partial_round_5;
    Nibble ** filtered_possible_keys = (Nibble**)malloc(sizeof(Nibble*));
    Nibble ** partial_delta_set;
    int count = 0;
    int size = nibbles_to_int(possible_keys[0], 8);
    free(possible_keys[0]);

    printf("\n\nPossible Partial Key(s)\n");
    for(int i = 1; i <= size ; i++){
        partial_delta_set = get_partial_delta_set(delta_set, col_num);
        partial_round_4 = copy_bytes(possible_keys[i],4);
        partial_round_5 = copy_bytes(&possible_keys[i][4],4);

        // Reverse Last 2 Rounds
        reverse_2_rounds(partial_delta_set, partial_round_5, partial_round_4);

        // Check Balance Property for Partial Delta Set
        bool is_balanced_for_all = is_partial_balanced(partial_delta_set);


        if (is_balanced_for_all){
            count ++;
            filtered_possible_keys = (Nibble **) realloc(filtered_possible_keys, (count + 1) * sizeof(Nibble*));
            filtered_possible_keys[count] = copy_bytes(partial_round_4, 4);
            printf("Round 4 - ");
            print_row(partial_round_4);
            printf("Round 5 - ");
            print_row(partial_round_5);
            printf("\n");
        }
        for(int j = 0; j < 16; j++)
            free(partial_delta_set[j]);

        free(partial_delta_set);
        free(possible_keys[i]);
        free(partial_round_4);
        free(partial_round_5);
    }

    free(possible_keys);
    filtered_possible_keys[0] = int_to_nibbles(count, 2);
    return filtered_possible_keys;
}

void full_key_integral_attack(Nibble ** delta_set1, Nibble ** delta_set2, Nibble * plaintext1, Nibble * plaintext2){
    Nibble * round_key_4 = (Nibble *) calloc(16, sizeof(Nibble));
    Nibble *** filtered_partial_keys = (Nibble ***) malloc(3*sizeof(Nibble **));
    int size[3];
    for(int col_num = 0; col_num < 3; col_num ++) {
        printf("\n");
        Nibble ** partial_keys = integral_attack_1(delta_set1, col_num);
        filtered_partial_keys[col_num] = integral_attack_2(delta_set2, partial_keys, col_num);
        size[col_num] = nibbles_to_int(filtered_partial_keys[col_num][0], 2);
        free(filtered_partial_keys[col_num][0]);
    }

    //Finding All Possible Keys after Three Column Attack and Last Column Exhaustive
    int i;
    printf("\nPossible Master Keys \n\n");
    for(i = 1; i <= size[0]; i++){
        for (int j = 1; j <= size[1] ; j ++){
            for (int k = 1; k <= size[2]; k++){
                for(int index = 0; index <4; index++){
                    round_key_4[index] = filtered_partial_keys[0][i][index];
                    round_key_4[4 + index] = filtered_partial_keys[1][j][index];
                    round_key_4[8 + index] = filtered_partial_keys[2][k][index];
                    for(int val = 0; val < pow(2, 16); val++){
                        Nibble * remaining_col = int_to_nibbles(val, 4);
                        for(int n = 0; n < 4; n++)
                            round_key_4[12 + n] = remaining_col[n];
                        Nibble * master_key = get_master_key(round_key_4, 4);
                        Nibble * ciphertext1 = aes_enc_ciphertext(plaintext1, master_key, 5);
                        Nibble * ciphertext2 = aes_enc_ciphertext(plaintext2, master_key, 5);
                        if(compare_state(ciphertext1, delta_set1[0]) && compare_state(ciphertext2, delta_set2[0]))
                            print_state_matrix(master_key);
                        free(master_key);
                        free(ciphertext1);
                        free(ciphertext2);
                        free(remaining_col);
                    }
                }
            }
        }
    }
    printf("\n");
    for(i = 1; i <= size[0]; i++)   free(filtered_partial_keys[0][i]);
    for(i = 1; i <= size[1]; i++)   free(filtered_partial_keys[1][i]);
    for(i = 1; i <= size[2]; i++)   free(filtered_partial_keys[2][i]);

    for(i = 0; i < 3; i++)    free(filtered_partial_keys[i]);
    free(filtered_partial_keys);
}

#endif