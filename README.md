# SPE_PP

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

To run the program :

- $g++ BT17CSE043_lab3.cpp -lpbc -lgmp
- $./a.out    
