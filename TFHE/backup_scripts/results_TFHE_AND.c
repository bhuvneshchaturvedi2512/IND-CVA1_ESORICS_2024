#define _POSIX_C_SOURCE 200809L

#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

long pos_threshold = 536870912;
long neg_threshold = 100394860544;

int count;
int no_of_attempts = 6;
int reactions = 0;

TFheGateBootstrappingParameterSet* params;//TFHE parameters
TFheGateBootstrappingSecretKeySet* key;//secret key
TFheGateBootstrappingCloudKeySet* bk;//bootstrapping key
LweSample* ciphertext1;
LweSample* ciphertext2;
LweSample* result;

void delete_ciphertexts()
{
	//clean up all pointers
    	delete_gate_bootstrapping_ciphertext_array(1, result);
    	delete_gate_bootstrapping_ciphertext_array(1, ciphertext1);
    	delete_gate_bootstrapping_ciphertext_array(1, ciphertext2);
}

void get_ciphertexts()
{
	int plaintext1,plaintext2;
  	plaintext1 = rand()%2;
  	plaintext2 = rand()%2;
  	
  	ciphertext1 = new_gate_bootstrapping_ciphertext_array(1, params);
  	ciphertext2 = new_gate_bootstrapping_ciphertext_array(1, params);
  	result = new_gate_bootstrapping_ciphertext_array(1, params);
  
  	for (int j=0; j<1; j++) {
            bootsSymEncrypt(&ciphertext1[j], (plaintext1>>j)&1, key);
    	}
  	for (int k=0; k<1; k++) {
            bootsSymEncrypt(&ciphertext2[k], (plaintext2>>k)&1, key);
    	}
  
  	bootsAND(result, &ciphertext1[0], &ciphertext2[0], bk);
}

void get_s_j(int j)
{
	FILE *generated_key;
	int ans_original, ans_incorrect, ans;
	for(int i = 1; i <= no_of_attempts; ++i)
	{
		get_ciphertexts();
		ans_original = bootsSymDecrypt(result, key); //correct answer
		
		if(ans_original == 0)
    		{
    			ans_incorrect = 1;
    		}
    		else if(ans_original == 1)
    		{
    			ans_incorrect = 0;
    		}
    		
    		result[0].a[j] = result[0].a[j] + neg_threshold;
    		ans = bootsSymDecrypt(result, key);
    		count = count + 1;
    		result[0].a[j] = result[0].a[j] - neg_threshold;
    		
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
		ans_original = bootsSymDecrypt(result, key); //correct answer
		
		if(ans_original == 0)
    		{
    			ans_incorrect = 1;
    		}
    		else if(ans_original == 1)
    		{
    			ans_incorrect = 0;
    		}
    		
    		result[0].a[j] = result[0].a[j] - pos_threshold;
        	ans = bootsSymDecrypt(result, key);
        	count = count + 1;        
        	result[0].a[j] = result[0].a[j] + pos_threshold;
    		
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


