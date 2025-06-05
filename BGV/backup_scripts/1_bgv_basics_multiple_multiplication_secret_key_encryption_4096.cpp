// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"

using namespace std;
using namespace seal;

uint64_t q = 68719403009;

uint64_t neg_threshold = 512000;
uint64_t pos_threshold = 512000;

int count_queries;
int no_of_attempts = 20;
int reactions = 0;

void example_bgv_basics()
{

    srand(967); //srand(967); srand(1073); srand(2512); srand(2406); srand(2022); for testing.
    
    print_example_banner("Example: BGV Basics");

    EncryptionParameters parms(scheme_type::bgv);

    size_t poly_modulus_degree = 4096;
    parms.set_poly_modulus_degree(poly_modulus_degree);

    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));

    parms.set_plain_modulus(1024);

    SEALContext context(parms);

    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    
    /*PublicKey public_key;
    keygen.create_public_key(public_key);*/
    
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    
    uint64_t x;
    uint64_t y;
    uint64_t z;

    Encryptor encryptor(context, secret_key);

    Evaluator evaluator(context);

    Decryptor decryptor(context, secret_key);
    
    Ciphertext x_encrypted;
    Ciphertext y_encrypted;
    Ciphertext z_encrypted;
    Ciphertext x_times_y;
    Ciphertext x_times_y_times_z;
    Ciphertext x_times_y_times_z_next;
    
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
    		z = rand() % 4;
    	
    		data_points = fopen("data_points.csv", "a");
    		fprintf(data_points, "%ld,%ld,%ld\n", x, y, z);
    		fclose(data_points);
    
    		Plaintext x_plain(uint64_to_hex_string(x));
    		Plaintext y_plain(uint64_to_hex_string(y));
    		Plaintext z_plain(uint64_to_hex_string(z));
		
		encryptor.encrypt(x_plain, x_encrypted);
    		encryptor.encrypt(y_plain, y_encrypted);
    		encryptor.encrypt(z_plain, z_encrypted);
    	
    		evaluator.multiply(x_encrypted, y_encrypted, x_times_y);
    		evaluator.relinearize_inplace(x_times_y, relin_keys);
    		evaluator.multiply(x_times_y, z_encrypted, x_times_y_times_z);
    		evaluator.relinearize_inplace(x_times_y_times_z, relin_keys);
    		evaluator.mod_switch_to_next(x_times_y_times_z, x_times_y_times_z_next);
    		
		decryptor.decrypt(x_times_y_times_z_next, ans_original);
		
		//ans_incorrect = (ans_original.data()[i] + 1) % 1024;
  		
    		x_times_y_times_z_next.data(1)[0] = (x_times_y_times_z_next.data(1)[0] + 34359296000) % q;
    		x_times_y_times_z_next.data()[i] = (x_times_y_times_z_next.data()[i] + pos_threshold) % q;
    		
    		decryptor.decrypt(x_times_y_times_z_next, ans);
    		count_queries = count_queries + 1;
    		
    		if(ans.data()[i] != ans_original.data()[i])//perturbation causes result to flip
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
    		z = rand() % 4;
    	
    		data_points = fopen("data_points.csv", "a");
    		fprintf(data_points, "%ld,%ld,%ld\n", x, y, z);
    		fclose(data_points);
    
    		Plaintext x_plain(uint64_to_hex_string(x));
    		Plaintext y_plain(uint64_to_hex_string(y));
    		Plaintext z_plain(uint64_to_hex_string(z));
		
		encryptor.encrypt(x_plain, x_encrypted);
    		encryptor.encrypt(y_plain, y_encrypted);
    		encryptor.encrypt(z_plain, z_encrypted);
    	
    		evaluator.multiply(x_encrypted, y_encrypted, x_times_y);
    		evaluator.relinearize_inplace(x_times_y, relin_keys);
    		evaluator.multiply(x_times_y, z_encrypted, x_times_y_times_z);
    		evaluator.relinearize_inplace(x_times_y_times_z, relin_keys);
    		evaluator.mod_switch_to_next(x_times_y_times_z, x_times_y_times_z_next);
    		
		decryptor.decrypt(x_times_y_times_z_next, ans_original);
		
		//ans_incorrect = (ans_original.data()[i] - 1) % 1024;

    		x_times_y_times_z_next.data(1)[0] = (x_times_y_times_z_next.data(1)[0] + 34359296000) % q;
    		x_times_y_times_z_next.data()[i] = (x_times_y_times_z_next.data()[i] - neg_threshold) % q;
    		
    		decryptor.decrypt(x_times_y_times_z_next, ans);
    		count_queries = count_queries + 1;
    		
    		if(ans.data()[i] != ans_original.data()[i])//perturbation causes result to flip
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
