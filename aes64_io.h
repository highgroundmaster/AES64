#ifndef AES64_IO_H
#define AES64_IO_H

// Libraries
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>


// CONSTANTS
typedef unsigned char Nibble;
const Nibble S_BOX[16] =
        {
                0x6, 0xb, 0x5, 0x4,
                0x2, 0xe, 0x7, 0xa,
                0x9, 0xd, 0xf, 0xc,
                0x3, 0x1, 0x0, 0x8
        };

const Nibble INV_S_BOX[16] = {
        0xe, 0xd, 0x4, 0xc,
        0x3, 0x2, 0x0, 0x6,
        0xf, 0x8, 0x7, 0x1,
        0xB, 0x9, 0x5, 0xa
};

const Nibble R_CONS[10] = {
        0x1, 0x2, 0x4, 0x8, 0x3,
        0x6, 0xc,0xb, 0x5, 0xa
};

const Nibble MIX_COLUMNS[3][16] =
        {
                {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf}, // 1
                {0x0, 0x2, 0x4, 0x6, 0x8, 0xa, 0xc, 0xe, 0x3, 0x1, 0x7, 0x5, 0xb, 0x9, 0xf, 0xd}, // 2
                {0x0, 0x3, 0x6, 0x5, 0xc, 0xf, 0xa, 0x9, 0xb, 0x8, 0xd, 0xe, 0x7, 0x4, 0x1, 0x2}  // 3
        };


const Nibble INV_MIX_COLUMNS[4][16] =
        {
                {0x0, 0x9, 0x1, 0x8, 0x2, 0xb, 0x3, 0xa, 0x4, 0xd, 0x5, 0xc, 0x6, 0xf, 0x7, 0xe},  // 9
                {0x0, 0xb, 0x5, 0xe, 0xa, 0x1, 0xf, 0x4, 0x7, 0xc, 0x2, 0x9, 0xd, 0x6, 0x8, 0x3},  //11
                {0x0, 0xd, 0x9, 0x4, 0x1, 0xc, 0x8, 0x5, 0x2, 0xf, 0xb, 0x6, 0x3, 0xe, 0xa, 0x7},  //13
                {0x0, 0xe, 0xf, 0x1, 0xd, 0x3, 0x2, 0xc, 0x9, 0x7, 0x6, 0x8, 0x4, 0xa, 0xb, 0x5}   //14
        };

/* Specify how wide the progress bar should be. */
#define PROGRESS_BAR_WIDTH 50

/* Various unicode character definitions. */
#define BAR_START "[ \u2595"
#define BAR_STOP  "\u258F ]"
#define PROGRESS_BLOCK     "\u2588"


static const char * sub_progress_blocks[] = { " ",
                                              "\u258F",
                                              "\u258E",
                                              "\u258D",
                                              "\u258C",
                                              "\u258B",
                                              "\u258A",
                                              "\u2589"
};

#define NUM_SUB_BLOCKS (sizeof(sub_progress_blocks) / sizeof(sub_progress_blocks[0]))

// Utility Functions

/*
    Copies and returns the copy of an n-Nibble Array
*/
Nibble * copy_bytes(const Nibble * mat, int n){
    Nibble * copy = (Nibble *)malloc(n);
    for (int i = 0; i < n ; i++)
        copy[i] = mat[i];
    return copy;
}

/*
 Returns Len number of Bytes containing the value provided in Nibble form
*/
Nibble * int_to_nibbles(int num, const int len){
    if(num >= pow(16, (double)len)){
        printf("Error : Given Number being the bounds of 4 Nibble Capacity\n");
        exit(1);
    }
    Nibble * nibbles =  (Nibble *) malloc(len);
    for(int i= 0 ; i < len; i++){
        nibbles[len - i - 1] = num % 16;
        num = num / 16;
    }
    return nibbles;
}

int nibbles_to_int(const Nibble * nibbles, int len){
    int num = 0, exp_factor = 1;
    for(int i= 0 ; i < len; i++)
    {
        num += exp_factor * nibbles[len - i - 1];
        exp_factor *= 16;
    }
    return num;
}

Nibble * hex_string_to_nibble(const char* hex_string, const int len){
    Nibble * state = (Nibble *)calloc(len, sizeof(Nibble));
    char c;
    for(int i =0; i < len; i++){
        c = hex_string[i];
        if(c == 0)   break;
        state[i] = (Nibble)strtol(&c, NULL, 16);
    }
    return state;
}

Nibble * hex_string_to_state(const char* hex_string){
    return hex_string_to_nibble(hex_string, 16);
}

Nibble * scan_hex(int len){
    Nibble hex_string[len + 1];
    fgets((char*)hex_string, sizeof(hex_string), stdin);
    Nibble * state = hex_string_to_nibble((char*)hex_string, len);
    int c;
    while ((c = getchar()) != EOF && c != '\n' );
    return state;
}


Nibble * scan_state(){
    return scan_hex(16);
}

void print_row(const Nibble * row){
    for (int i = 0; i < 4; i++)
        printf("0x%01x ",row[i]);

    printf("\n");
}

/*
    Prints a State Matrix in Column Major Format from a 16-Nibble Array
*/
void print_state_matrix(const Nibble * state){

    for (int i = 0; i < 4; i++){
        for (int j = 0; j < 4; j++){
            printf("0x%01x ", state[j * 4 + i]);
        }
        printf("\n");
    }
    printf("\n");
}

bool compare_state(const Nibble * state1, const Nibble * state2){
    for(int i =0; i < 16; i++)
        if(state1[i] != state2[i])  return 0;
    return 1;
}

void set_bit( Nibble * counter,  int key_index)
{
    counter[key_index / 8] |= 1 << (key_index % 8);  // Set the bit at the k-th position in Counter[i]
}

int get_bit( Nibble * counter,  int key_index )
{
    return ( (counter[key_index / 8] & (1 << (key_index % 8) )) != 0 ) ;
}
/*
 * Main interface function for updating the progress bar.
 * Call it iteratively and have the progress bar grow across the screen
 * percentage: a double between 0.0 and 100.0 indicating the progress.
 */
void print_progress(double percentage, const char* label) {
    size_t i;
    size_t total_blocks = PROGRESS_BAR_WIDTH * NUM_SUB_BLOCKS;
    size_t done = (size_t)round(percentage / 100.0 * (double)total_blocks);
    size_t num_blocks = done / NUM_SUB_BLOCKS;
    size_t num_sub_blocks = done % NUM_SUB_BLOCKS;


    printf("   %s (%.2f%%)  %s", label, percentage, BAR_START);

    for (i = 0; i < num_blocks; i++) {
        printf("%s", PROGRESS_BLOCK);
    }

    if (num_sub_blocks) {
        printf("%s", sub_progress_blocks[num_sub_blocks]);
        i++;
    }

    for (; i < PROGRESS_BAR_WIDTH; i++) {
        printf(" ");
    }

    printf("%s\t", BAR_STOP);

    printf("\r");
    fflush(stdout);
}
#endif
