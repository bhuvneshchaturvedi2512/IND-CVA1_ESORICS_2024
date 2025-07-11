// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"

using namespace std;
using namespace seal;

uint64_t neg_threshold = 4398046507008;
uint64_t pos_threshold = 4398046507009;

int count_queries;
int no_of_attempts = 20;
int reactions = 0;

void example_bfv_basics()
{

    srand(967); //srand(967); srand(1073); srand(2512); srand(2406); srand(2022); for testing.
    
    print_example_banner("Example: BFV Basics");

    EncryptionParameters parms(scheme_type::bfv);

    size_t poly_modulus_degree = 2048;
    parms.set_poly_modulus_degree(poly_modulus_degree);

    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));

    parms.set_plain_modulus(1024);

    SEALContext context(parms);

    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    
    /*PublicKey public_key;
    keygen.create_public_key(public_key);*/
    
    uint64_t x;
    uint64_t y;

    Encryptor encryptor(context, secret_key);

    Evaluator evaluator(context);

    Decryptor decryptor(context, secret_key);
    
    Ciphertext x_encrypted;
    Ciphertext y_encrypted;
    
    Plaintext ans_original, ans;
    	
    uint64_t ans_incorrect;
    
    FILE *generated_key;
    FILE *data_points;
    
    int flag_1, flag_2;
    
    for(int i = 0; i < poly_modulus_degree; ++i) 
    {
    
    	count_queries = 0;
    	cout << "Retrieving s[" << i << "]" << endl;
    	
    	for(int j = 1; j <= no_of_attempts; ++j)
	{
		flag_1 = 0;
		
		x = rand() % 4;
    		y = rand() % 4;
    	
    		data_points = fopen("data_points.csv", "a");
    		fprintf(data_points, "%ld,%ld\n", x, y);
    		fclose(data_points);
    
    		Plaintext x_plain(uint64_to_hex_string(x));
    		Plaintext y_plain(uint64_to_hex_string(y));
		
		encryptor.encrypt(x_plain, x_encrypted);
    		encryptor.encrypt(y_plain, y_encrypted);
    	
    		evaluator.multiply_inplace(x_encrypted, y_encrypted);
    		
		decryptor.decrypt(x_encrypted, ans_original);
		
		ans_incorrect = (ans_original.data()[i] + 1) % 1024;
  		
    		x_encrypted.data(1)[0] = x_encrypted.data(1)[0] + 4398046507008;
    		x_encrypted.data()[i] = x_encrypted.data()[i] + pos_threshold;
    		
    		decryptor.decrypt(x_encrypted, ans);
    		count_queries = count_queries + 1;
    		
    		if(ans.data()[i] == ans_incorrect)//perturbation causes result to flip
    		{
			generated_key = fopen("generated_key.txt","a");
        		fprintf(generated_key, "%d ", 1);
        		fclose(generated_key);
        		reactions = reactions + 1;
        		
        		flag_1 = 1;
        		break;
    		}
	}
	
	if(flag_1 == 1)
	{
		FILE* count_of_oracle_accesses = fopen("count_of_oracle_accesses.csv","a");
    		fprintf(count_of_oracle_accesses, "%d\n", count_queries);
    		fclose(count_of_oracle_accesses);
		continue;
	}
	
	for(int j = 1; j <= no_of_attempts; ++j)
	{
		flag_2 = 0;
		
		x = rand() % 4;
    		y = rand() % 4;
    	
    		data_points = fopen("data_points.csv", "a");
    		fprintf(data_points, "%ld,%ld\n", x, y);
    		fclose(data_points);
    
    		Plaintext x_plain(uint64_to_hex_string(x));
    		Plaintext y_plain(uint64_to_hex_string(y));
		
		encryptor.encrypt(x_plain, x_encrypted);
    		encryptor.encrypt(y_plain, y_encrypted);
    	
    		evaluator.multiply_inplace(x_encrypted, y_encrypted);
    		
		decryptor.decrypt(x_encrypted, ans_original);
		
		ans_incorrect = (ans_original.data()[i] - 1) % 1024;

    		x_encrypted.data(1)[0] = x_encrypted.data(1)[0] + 4398046507008;
    		x_encrypted.data()[i] = x_encrypted.data()[i] - neg_threshold;
    		
    		decryptor.decrypt(x_encrypted, ans);
    		count_queries = count_queries + 1;
    		
    		if(ans.data()[i] == ans_incorrect)//perturbation causes result to flip
    		{
			generated_key = fopen("generated_key.txt","a");
        		fprintf(generated_key, "%d ", -1);
        		fclose(generated_key);
        		reactions = reactions + 1;
        		
        		flag_2 = 1;
        		break;
    		}
	}
	
	if(flag_2 == 0)
	{
		generated_key = fopen("generated_key.txt","a");
        	fprintf(generated_key, "%d ", 0);
        	fclose(generated_key);
        }
    	
    	FILE* count_of_oracle_accesses = fopen("count_of_oracle_accesses.csv","a");
    	fprintf(count_of_oracle_accesses, "%d\n", count_queries);
    	fclose(count_of_oracle_accesses);
	
    }
    cout << "No. of reactions: " << reactions << "\n" << endl;

}
