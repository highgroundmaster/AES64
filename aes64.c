//Libraries
#include <stdlib.h>
#include <stdbool.h>
#include <math.h>
#include "aes64_key_expansion.h"
#include "aes64_enc_dec.h"
#include "aes64_impossible.h"
#include "aes64_integral.h"
#include "aes64_cfb.h"


void help(){
    FILE * fptr = fopen("MAN.txt", "r");
    if (fptr == NULL)
    {
        printf("Cannot open file \n");
        exit(0);
    }

    // Read contents from file
    char c = (char)fgetc(fptr);
    while (c != EOF)
    {
        printf ("%c", c);
        c = (char)fgetc(fptr);
    }

    fclose(fptr);
}

int main(int argc, char const *argv[])
 {
     if( argc == 1 || strcmp(argv[1],"-h") == 0 || strcmp(argv[1],"--help") == 0)
         help();

     //Verbose
     else if(strcmp(argv[1],"-v") == 0 || strcmp(argv[1],"--verbose") == 0){
         if(argc < 3 || argv[2][0] != '-'){
             printf("Invalid Usage : No command selected\n");
             help();
             exit(1);
         }

         //Encryption
         else if(strcmp(argv[2],"-e") == 0 || strcmp(argv[2],"--encrypt") == 0){
             Nibble * master_key, * plaintext;
             if(argc < 4){
                 printf("Enter the Master Key Block in 16 Character Hexadecimal Stream form:\n");
                 master_key = scan_state();
                 printf("Enter the Plaintext Block in 16 Character Hexadecimal Stream form:\n");
                 plaintext = scan_state();
             }

             else if(argc == 4){
                 master_key = hex_string_to_state(argv[3]);
                 printf("Enter the Plaintext Block in 16 Character Hexadecimal Stream form:\n");
                 plaintext = scan_state();
             }

             else{
                 master_key = hex_string_to_state(argv[3]);
                 plaintext = hex_string_to_state(argv[4]);
             }
             Nibble * ciphertext = aes_enc_test(plaintext, master_key, 1);
             printf("Encrypted Ciphertext\n");
             for (int i = 0; i < 16; i++)
                 printf("%01x",ciphertext[i]);
             printf("\n\n");

             free(ciphertext);
             free(plaintext);
             free(master_key);
         }

         // Decryption
         else if(strcmp(argv[2],"-d") == 0 || strcmp(argv[2],"--decrypt") == 0){
             Nibble * master_key, * ciphertext;
             if(argc < 4){
                 printf("Enter the Master Key Block in 16 Character Hexadecimal Stream form:\n");
                 master_key = scan_state();
                 printf("Enter the Ciphertext Block in 16 Character Hexadecimal Stream form:\n");
                 ciphertext = scan_state();
             }

             else if(argc == 4){
                 master_key = hex_string_to_state(argv[3]);
                 printf("Enter the Ciphertext Block in 16 Character Hexadecimal Stream form:\n");
                 ciphertext = scan_state();
             }

             else{
                 master_key = hex_string_to_state(argv[3]);
                 ciphertext = hex_string_to_state(argv[4]);
             }
             Nibble * plaintext = aes_dec_test(ciphertext, master_key, 1);
             printf("Decrypted Plaintext\n");
             for (int i = 0; i < 16; i++)
                 printf("%01x",plaintext[i]);
             printf("\n\n");

             free(ciphertext);
             free(plaintext);
             free(master_key);
         }

         //Integral Property
         else if(strcmp(argv[2],"-ip") == 0 || strcmp(argv[2],"--integral-property") == 0){
             Nibble * constants, * master_key, ** delta_set, values[16];
             int i, index;
             if(argc < 4){
                 printf("Enter the ALL Property Index:\n");
                 scanf("%d", &index);
                 while ((i = getchar()) != EOF && i != '\n' );
                 printf("Enter the CONSTANT Values in 15 Character Hexadecimal Stream form:\n");
                 constants = scan_hex(15);
                 printf("Enter the Master Key Block in 16 Character Hexadecimal Stream form:\n");
                 master_key = scan_state();
             }

             else if(argc ==4){
                 index = (int)strtol(argv[3], NULL, 10);
                 printf("Enter the CONSTANT Values in 15 Character Hexadecimal Stream form:\n");
                 constants = scan_hex(15);
                 printf("Enter the Master Key Block in 16 Character Hexadecimal Stream form:\n");
                 master_key = scan_state();
             }

             else if(argc == 5){
                 index = (int)strtol(argv[3], NULL, 10);
                 constants = hex_string_to_nibble(argv[4], 15);
                 printf("Enter the Master Key Block in 16 Character Hexadecimal Stream form:\n");
                 master_key = scan_state();
             }

             else{
                 index = (int)strtol(argv[3], NULL, 10);
                 constants = hex_string_to_state(argv[4]);
                 master_key = hex_string_to_state(argv[5]);
             }
             for(i = 0; i < 15; i++){
                 if(i < index)   values[i] = constants[i];
                 else values[i+1] = constants[i];
             }
             values[index] = -1;
             delta_set = get_delta_set(values);

             printf("\nPlaintexts\n");
             for (i = 0; i < 16; i++){
                 for(int j = 0; j < 16; j++)
                     printf("%01x",delta_set[i][j]);
                 printf("\n");
             }
             printf("\n\n");

             aes_delta_enc_5(delta_set, master_key, 1);

             printf("\nCiphertexts\n");
             for (i = 0; i < 16; i++){
                 for(int j = 0; j < 16; j++)
                     printf("%01x",delta_set[i][j]);
                 printf("\n");
             }
             printf("\n");

             for(i = 0; i < 16; i++) free(delta_set[i]);
             free(master_key);
             free(constants);
             free(delta_set);
         }

         //CFB
         else if(strcmp(argv[2],"-c") == 0 || strcmp(argv[2],"--cfb") == 0){
             cfb_test(1,0);
         }

         //CFB Error Propagation
         else if(strcmp(argv[2],"-ce") == 0 || strcmp(argv[2],"--cfb-error") == 0){
             cfb_test(1,1);
         }


     }

     //Encryption
     else if(strcmp(argv[1],"-e") == 0 || strcmp(argv[1],"--encrypt") == 0){
         Nibble * master_key, * plaintext;
         if(argc < 3){
             printf("Enter the Master Key Block in 16 Character Hexadecimal Stream form:\n");
             master_key = scan_state();
             printf("Enter the Plaintext Block in 16 Character Hexadecimal Stream form:\n");
             plaintext = scan_state();
         }

         else if(argc == 3){
             master_key = hex_string_to_state(argv[2]);
             printf("Enter the Plaintext Block in 16 Character Hexadecimal Stream form:\n");
             plaintext = scan_state();
         }

         else{
             master_key = hex_string_to_state(argv[2]);
             plaintext = hex_string_to_state(argv[3]);
         }
         Nibble * ciphertext = aes_enc_test(plaintext, master_key, 0);
         printf("\nEncrypted Ciphertext\n");
         for (int i = 0; i < 16; i++)
             printf("%01x",ciphertext[i]);
         printf("\n\n");

         free(ciphertext);
         free(plaintext);
         free(master_key);
     }

     // Decryption
     else if(strcmp(argv[1],"-d") == 0 || strcmp(argv[1],"--decrypt") == 0){
         Nibble * master_key, * ciphertext;
         if(argc < 3){
             printf("Enter the Master Key Block in 16 Character Hexadecimal Stream form:\n");
             master_key = scan_state();
             printf("Enter the Ciphertext Block in 16 Character Hexadecimal Stream form:\n");
             ciphertext = scan_state();
         }

         else if(argc == 3){
             master_key = hex_string_to_state(argv[2]);
             printf("Enter the Ciphertext Block in 16 Character Hexadecimal Stream form:\n");
             ciphertext = scan_state();
         }

         else{
             master_key = hex_string_to_state(argv[2]);
             ciphertext = hex_string_to_state(argv[3]);
         }
         Nibble * plaintext = aes_dec_test(ciphertext, master_key, 0);
         printf("\nDecrypted Plaintext\n");
         for (int i = 0; i < 16; i++){
             printf("%01x",plaintext[i]);
         }
         printf("\n\n");

         free(ciphertext);
         free(plaintext);
         free(master_key);
     }
     //Structure Encryption
     else if(strcmp(argv[1],"-s") == 0 || strcmp(argv[1],"--structure") == 0){
         Nibble * master_key, *constants, ** structure;
         Nibble ** ciphertexts = (Nibble **) malloc( pow(2, 16)* sizeof(Nibble *));
         int diagonal;

         if(argc < 3) {
             printf("Enter the Diagonal you want to do the Attack on:\n");
             scanf("%d", &diagonal);
             printf("Enter the Master Key Block in 16 Character Hexadecimal Stream form:\n");

             master_key = scan_state();
             printf("Enter Structure Constants in 12 Hexadecimal Stream\n");
             constants = scan_hex(12);
             structure = generate_structure(constants, 0);
             free(constants);
         }
         else if(argc == 3){
             diagonal = (int)strtol(argv[2], NULL, 10);
             if(diagonal > 3){
                 printf("Diagonal value %d should be less than or equal to 3", diagonal);
                 help();
                 exit(1);
             }
             printf("Enter the Master Key Block in 16 Character Hexadecimal Stream form:\n");
             master_key = scan_state();
             printf("Enter Structure Constants in 12 Hexadecimal Stream\n");
             constants = scan_hex(12);
             structure = generate_structure(constants, 0);
             free(constants);

         }
         else if(argc == 4){
             diagonal = (int)strtol(argv[2], NULL, 10);
             if(diagonal > 3){
                 printf("Diagonal value %d should be less than or equal to 3", diagonal);
                 help();
                 exit(1);
             }
             master_key = hex_string_to_state(argv[2]);
             printf("Enter Structure Constants in 12 Hexadecimal Stream\n");
             constants = scan_hex(12);
             structure = generate_structure(constants, 0);
             free(constants);
         }
         else{
             diagonal = (int)strtol(argv[2], NULL, 10);
             if(diagonal > 3){
                 printf("Diagonal value %d should be less than or equal to 3", diagonal);
                 help();
                 exit(1);
             }
             master_key = hex_string_to_state(argv[3]);
             constants = hex_string_to_nibble(argv[4], 12);
             structure = generate_structure(constants, diagonal);
             free(constants);
         }

         printf("\nPlaintexts in Stream Form\n");
         for(int i = 0; i < pow(2,16); i++){
             for (int j = 0; j < 16; j++)
                 printf("%01x",structure[i][j]);
             printf("\n");

         }
         printf("\n");

         printf("Corresponding Ciphertexts in Stream Form\n");
         for(int i = 0; i < pow(2,16); i++){
             ciphertexts[i] = aes_enc_5(structure[i], master_key);
             for (int j = 0; j < 16; j++) {
                 printf("%01x",ciphertexts[i][j]);
             }
             printf("\n");

             free(structure[i]);
             free(ciphertexts[i]);
         }
         printf("\n");

         free(structure);
         free(master_key);
         free(ciphertexts);
     }

     //Impossible Differential Attack
     else if(strcmp(argv[1],"-id") == 0 || strcmp(argv[1],"--impossible-differential") == 0){

         Nibble * constants, ** structure1, **structure2 ;
         Nibble ** ciphertexts1 = (Nibble **) malloc( pow(2, 16)* sizeof(Nibble *));
         Nibble ** ciphertexts2 = (Nibble **) malloc( pow(2, 16)* sizeof(Nibble *));
         int diagonal;

         if(argc < 3) {
             printf("Enter the Diagonal you want to do the Attack on:\n");
             scanf("%d", &diagonal);
         }
         else if(argc == 3)
             diagonal = (int)strtol(argv[2], NULL, 10);

         if(diagonal > 3){
             printf("Diagonal value %d should be less than or equal to 3", diagonal);
             help();
             exit(1);
         }
         printf("Enter Structure - 1 Constants in 12 Hexadecimal Character\n");
         constants = scan_hex(12);
         structure1 = generate_structure(constants, diagonal);
         free(constants);

         printf("Enter Structure - 2 Constants in 12 Hexadecimal Character\n");
         constants = scan_hex(12);
         structure2 = generate_structure(constants, diagonal);
         free(constants);

         printf("Enter Corresponding Ciphertexts of Structure - 1 in 16 Hexadecimal Stream\n");
         for(int i = 0; i < pow(2,16); i++)
             ciphertexts1[i] = scan_state();

         printf("Enter Corresponding Ciphertexts of Structure - 2 in 16 Hexadecimal Stream\n");
         for(int i = 0; i < pow(2,16); i++)
             ciphertexts2[i] = scan_state();

         printf("\nGenerating Conforming Pairs for Structure 1\n");
         Nibble ** conforming_pairs = get_conforming_pairs(structure1, ciphertexts1, diagonal);
         printf("\nGenerating Conforming Pairs for Structure 2\n");
         Nibble ** conforming_pairs2 = get_conforming_pairs(structure2, ciphertexts2, diagonal);

         int size1 = nibbles_to_int(conforming_pairs[0], 16);
         int size2 = nibbles_to_int(conforming_pairs2[0], 16);
         conforming_pairs = (Nibble **)realloc(conforming_pairs, (size1 + size2 + 1) * sizeof(Nibble*));

         for (int i = 1; i <= size2; i++)
             conforming_pairs[size1 + i] = conforming_pairs2[i];

         // Freeing the Sizes to resize the Conforming Pairs
         free(conforming_pairs[0]);
         free(conforming_pairs2[0]);

         conforming_pairs[0] = int_to_nibbles(size1 + size2, 16);
         free(conforming_pairs2);

         Nibble * counter = recovery(conforming_pairs, diagonal);
         printf("\nSubKey Recovery of diagonal %d\n", diagonal);
         Nibble key[16] = {[0 ... 15] = 0};
         for(int i = 0; i < pow(2,16); i++){
             if(!get_bit(counter, i)){
                 Nibble * sub_key = int_to_nibbles(i, 4);
                 Nibble * indexes = generate_diagonal_indexes(diagonal);
                 for (int j = 0; j < 4; j++) {
                     key[indexes[j]] = sub_key[j];
                 }
                 print_state_matrix(key);
                 free(sub_key);
                 free(indexes);
             }
             free(structure1[i]);
             free(structure2[i]);
             free(ciphertexts1[i]);
             free(ciphertexts2[i]);
         }

         for(int i = 0; i <= size1 + size2; i++)
             free(conforming_pairs[i]);

         free(conforming_pairs);
         free(counter);
         free(structure1);
         free(ciphertexts1);
         free(structure2);
         free(ciphertexts2);
     }

     //Integral Property
     else if(strcmp(argv[1],"-ip") == 0 || strcmp(argv[1],"--integral-property") == 0){
         Nibble * constants, * master_key, ** delta_set, values[16] ;
         int i, index;
         if(argc < 3){
             printf("Enter the ALL Property Index:\n");
             scanf("%d", &index);
             while ((i = getchar()) != EOF && i != '\n' );
             printf("Enter the CONSTANT Values in 15 Character Hexadecimal Stream form:\n");
             constants = scan_hex(15);
             printf("Enter the Master Key Block in 16 Character Hexadecimal Stream form:\n");
             master_key = scan_state();
         }

         else if(argc ==3){
             index = (int)strtol(argv[2], NULL, 10);
             printf("Enter the CONSTANT Values in 15 Character Hexadecimal Stream form:\n");
             constants = scan_hex(15);
             printf("Enter the Master Key Block in 16 Character Hexadecimal Stream form:\n");
             master_key = scan_state();
         }

         else if(argc == 4){
             index = (int)strtol(argv[2], NULL, 10);
             constants = hex_string_to_nibble(argv[3], 15);
             printf("Enter the Master Key Block in 16 Character Hexadecimal Stream form:\n");
             master_key = scan_state();
         }

         else{
             index = (int)strtol(argv[2], NULL, 10);
             constants = hex_string_to_nibble(argv[3], 15);
             master_key = hex_string_to_state(argv[4]);
         }
         for(i = 0; i < 15; i++){
             if(i < index)   values[i] = constants[i];
             else values[i+1] = constants[i];
         }
         values[index] = -1;
         delta_set = get_delta_set(values);

         printf("\nPlaintexts\n");
         for (i = 0; i < 16; i++){
             for(int j = 0; j < 16; j++)
                 printf("%01x",delta_set[i][j]);
             printf("\n");
         }
         printf("\n\n");

         aes_delta_enc_5(delta_set, master_key, 0);

         printf("\nCiphertexts\n");
         for (i = 0; i < 16; i++){
             for(int j = 0; j < 16; j++)
                 printf("%01x",delta_set[i][j]);
             printf("\n");
         }
         printf("\n");

         for(i = 0; i < 16; i++) free(delta_set[i]);
         free(master_key);
         free(constants);
         free(delta_set);
     }

         //Integral Attack
     else if(strcmp(argv[1],"-ia") == 0 || strcmp(argv[1],"--integral-attack") == 0){
         printf("Enter the Plaintext Delta Set 1\n");
         Nibble ** plaintext_delta_set1 = get_delta_set_hex();
         printf("\nEnter the corresponding Ciphertext Delta Set 1\n");
         Nibble ** ciphertext_delta_set1 = get_delta_set_hex();
         printf("\nEnter the Plaintext Delta Set 2\n");
         Nibble ** plaintext_delta_set2 = get_delta_set_hex();
         printf("\nEnter the corresponding Ciphertext Delta Set 2\n");
         Nibble ** ciphertext_delta_set2 = get_delta_set_hex();
         full_key_integral_attack(ciphertext_delta_set1, ciphertext_delta_set2, plaintext_delta_set1[0], plaintext_delta_set2[0]);
         for(int i = 0; i < 16; i++){
             free(plaintext_delta_set1[i]);
             free(plaintext_delta_set2[i]);
             free(ciphertext_delta_set1[i]);
             free(ciphertext_delta_set2[i]);
         }
         free(plaintext_delta_set1);
         free(plaintext_delta_set2);
         free(ciphertext_delta_set1);
         free(ciphertext_delta_set2);
     }

     //CFB
     else if(strcmp(argv[1],"-c") == 0 || strcmp(argv[1],"--cfb") == 0){
         cfb_test(0,0);
     }

     //CFB Error Propagation
     else if(strcmp(argv[1],"-ce") == 0 || strcmp(argv[1],"--cfb-error") == 0){
         cfb_test(0,1);
     }

     //Pseudo-Random Number Generator
     else if(strcmp(argv[1],"-r") == 0 || strcmp(argv[1],"--random") == 0){
         int count = 1;
         if(argc == 3)
             count = (int)strtol(argv[2], NULL, 10);
         for (int i = 0; i < count; ++i)
             system("openssl rand -hex 8");
     }

     // Invalid Arguments
     else{
         printf("Invalid Usage\n" );
         help();
         exit(1);
     }
    return 0;
 }
