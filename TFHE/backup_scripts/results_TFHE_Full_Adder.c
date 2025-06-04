#define _POSIX_C_SOURCE 200809L

#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

long pos_threshold = 9663676415;
long neg_threshold = 5368709119;

int count;
int no_of_attempts = 6;
int reactions = 0;

TFheGateBootstrappingParameterSet* params;//TFHE parameters
TFheGateBootstrappingSecretKeySet* key;//secret key
TFheGateBootstrappingCloudKeySet* bk;//bootstrapping key
LweSample* ciphertextA;
LweSample* ciphertextB;
LweSample* ciphertextC_in;
LweSample* Sum;
LweSample* C_out;

void delete_ciphertexts()
{
	//clean up all pointers
    	delete_gate_bootstrapping_ciphertext_array(1, Sum);
    	delete_gate_bootstrapping_ciphertext_array(1, C_out);
    	delete_gate_bootstrapping_ciphertext_array(1, ciphertextA);
    	delete_gate_bootstrapping_ciphertext_array(1, ciphertextB);
    	delete_gate_bootstrapping_ciphertext_array(1, ciphertextC_in);
}

void get_ciphertexts()
{
	int plaintext1,plaintext2,plaintext3;
  	plaintext1 = rand()%2;
  	plaintext2 = rand()%2;
  	plaintext3 = rand()%2;
  	
  	ciphertextA = new_gate_bootstrapping_ciphertext_array(1, params);
  	ciphertextB = new_gate_bootstrapping_ciphertext_array(1, params);
  	ciphertextC_in = new_gate_bootstrapping_ciphertext_array(1, params);
  	Sum = new_gate_bootstrapping_ciphertext_array(1, params);
  	C_out = new_gate_bootstrapping_ciphertext_array(1, params);
  
  	for (int j=0; j<1; j++) {
            bootsSymEncrypt(&ciphertextA[j], (plaintext1>>j)&1, key);
    	}
  	for (int j=0; j<1; j++) {
            bootsSymEncrypt(&ciphertextB[j], (plaintext2>>j)&1, key);
    	}
    	for (int j=0; j<1; j++) {
            bootsSymEncrypt(&ciphertextC_in[j], (plaintext3>>j)&1, key);
    	}
    	
    	LweSample* intermediate1 = new_gate_bootstrapping_ciphertext_array(1, params);
    	LweSample* intermediate2 = new_gate_bootstrapping_ciphertext_array(1, params);
    	LweSample* intermediate3 = new_gate_bootstrapping_ciphertext_array(1, params);
  
  	bootsXOR(intermediate1, &ciphertextA[0], &ciphertextB[0], bk);
    	bootsXOR(Sum, intermediate1, &ciphertextC_in[0], bk);
    
    	bootsAND(intermediate2, intermediate1, &ciphertextC_in[0], bk);
    	bootsAND(intermediate3, &ciphertextA[0], &ciphertextB[0], bk);
    	bootsOR(C_out, intermediate2, intermediate3, bk);
    	
    	delete_gate_bootstrapping_ciphertext_array(1, intermediate1);
    	delete_gate_bootstrapping_ciphertext_array(1, intermediate2);
    	delete_gate_bootstrapping_ciphertext_array(1, intermediate3);
}

void get_s_j(int j)
{
	FILE *generated_key;
	int ans_original, ans_incorrect, ans;
	for(int i = 1; i <= no_of_attempts; ++i)
	{
		get_ciphertexts();
		ans_original = bootsSymDecrypt(Sum, key); //correct answer
		
		if(ans_original == 0)
    		{
    			ans_incorrect = 1;
    		}
    		else if(ans_original == 1)
    		{
    			ans_incorrect = 0;
    		}
    		
    		Sum[0].a[j] = Sum[0].a[j] + neg_threshold;
    		ans = bootsSymDecrypt(Sum, key);
    		count = count + 1;
    		Sum[0].a[j] = Sum[0].a[j] - neg_threshold;
    		
    		if(ans == ans_incorrect)//perturbation causes result to flip
    		{
			generated_key = fopen("generated_key.txt","a");
        		fprintf(generated_key, "%d ", 1);
        		fclose(generated_key);
        		delete_ciphertexts();
        		reactions = reactions + 1;
        		return;
    		}
    		delete_ciphertexts();
	}
	for(int i = 1; i <= no_of_attempts; ++i)
	{
		get_ciphertexts();
		ans_original = bootsSymDecrypt(Sum, key); //correct answer
		
		if(ans_original == 0)
    		{
    			ans_incorrect = 1;
    		}
    		else if(ans_original == 1)
    		{
    			ans_incorrect = 0;
    		}
    		
    		Sum[0].a[j] = Sum[0].a[j] - pos_threshold;
        	ans = bootsSymDecrypt(Sum, key);
        	count = count + 1;        
        	Sum[0].a[j] = Sum[0].a[j] + pos_threshold;
    		
    		if(ans == ans_incorrect)//perturbation causes result to flip
    		{
			generated_key = fopen("generated_key.txt","a");
        		fprintf(generated_key, "%d ", 1);
        		fclose(generated_key);
        		delete_ciphertexts();
        		reactions = reactions + 1;
        		return;
    		}
    		delete_ciphertexts();
	}
	generated_key = fopen("generated_key.txt","a");
        fprintf(generated_key, "%d ", 0);
        fclose(generated_key);
	
}

int main(int argc, char *argv[]) {

  	srand(2022); //srand(967); srand(1073); srand(2512); srand(2406); srand(2022); for testing.
  	
  	printf("Setting up TFHE parameters\n");
  	
  	//generate a keyset
    	const int minimum_lambda = 110;
    	params = new_default_gate_bootstrapping_parameters(minimum_lambda);

    	printf("Generating keys ...\n");
    	
    	//generate a random key
    	uint32_t seed[] = { 101, 103, 107 }; //uint32_t seed[] = { 723, 4093, 106 }; uint32_t seed[] = { 1, 10132, 494 }; uint32_t seed[] = { 11, 29, 37 }; uint32_t seed[] = { 2, 3, 5 }; uint32_t seed[] = { 101, 103, 107 };
    	tfhe_random_generator_setSeed(seed,3);
    	key = new_random_gate_bootstrapping_secret_keyset(params);
    	bk = &key->cloud;
    	
  	printf("Done.\n");

  	for(int i = 0; i < 630; i++) {

    		count = 0;
    		printf("Retrieving s[%d]\n", i);
    		get_s_j(i);
    		FILE* count_of_oracle_accesses = fopen("count_of_oracle_accesses.csv","a");
    		fprintf(count_of_oracle_accesses, "%d\n", count);
    		fclose(count_of_oracle_accesses);
    		
    	}
    	printf("No. of reactions: %d\n", reactions);
    	//clean up all pointers
    	delete_gate_bootstrapping_secret_keyset(key);
    	delete_gate_bootstrapping_parameters(params);
}


