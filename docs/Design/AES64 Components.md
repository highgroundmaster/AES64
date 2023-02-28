# AES-64 Components

- $\text{AES}64$ implementation is done using C and `sage` .
---
## Galois Field

- **`sage`** is used to find the Galois products.
- For $\text{AES}64$, the galois field $GF(2^4)$ with irreducible polynomial $X^4 + X + 1$ is implemented under the name $l$
    
    ![aes_64_field.png](../Pictures/aes_64_field.png)
    
- Similarly for $\text{AES}128$, the galois field $GF(2^8)$ with irreducible polynomial $X^8 +X^4+ X^3+ X + 1$ is implemented under the name $k$ for verification
    
    ![aes_128.png](../Pictures/aes_128.png)
    
---
## Mix Columns and Inverse Mix Columns

- While the $\text{MDS}$ matrix stays the same, the vector-matrix multiplication is done using Galois Field Multiplication.
- Since for Mix Columns we only need to find the possible multiplication values for $1,2,3$, we can store those values in a lookup table for making the implementation fast
- The products are found using **`sage`**
    
    ![mix.png](../Pictures/mix.png)
    
- Here the functions `ntp()` and `ptn()` are custom functions defined the following way
    
    ![custom_function.png](../Pictures/custom_function.png)
    
- These products are then stored inside text files. We use $\text{AES}128$ to verify the process, and it gives correct answer
    
    ![mix_store.png](../Pictures/mix_store.png)
    
---
## Round Constant

- Round Constants are also found using Galois Field Multiplication with $0\texttt{x}2$ hence we use to find the product and store them in lookup table for faster implementation.
- We use the below function for finding Round constants
    
    ![r_con.png](../Pictures/r_con.png)
    
- It is then used to store inside a text file. We use $\text{AES}128$ to verify the process, and it gives correct answer.
    
    ![r_con_store.png](../Pictures/r_con_store.png)
    

