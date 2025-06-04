// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"

using namespace std;
using namespace seal;

int count_queries;
int reactions = 0;

void example_bfv_basics()
{

    srand(967); //srand(967); srand(1073); srand(2512); srand(2406); srand(2022); for testing.
    
    print_example_banner("Example: BFV Basics");

    EncryptionParameters parms(scheme_type::bfv);

    size_t poly_modulus_degree = 4096;
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
    	
    uint64_t ans_correct;
    
    FILE *generated_key;
    FILE *data_points;
    
    for(int i = 0; i < 4096; ++i) 
    {
    
    	count_queries = 0;
    	cout << "Retrieving s[" << i << "]" << endl;
		
	x = rand() % 4;
    	y = rand() % 4;
    	
    	data_points = fopen("data_points.csv", "a");
    	fprintf(data_points, "%ld,%ld\n", x, y);
    	fclose(data_points);
    
    	Plaintext x_plain(uint64_to_hex_string(x));
    	Plaintext y_plain(uint64_to_hex_string(y));
		
	encryptor.encrypt(x_plain, x_encrypted);
    	encryptor.encrypt(y_plain, y_encrypted);
    	
    	evaluator.add_inplace(x_encrypted, y_encrypted);
    		
	decryptor.decrypt(x_encrypted, ans_original);
		
	ans_correct = ans_original.data()[i];
  		
    	x_encrypted.data(1)[0] = x_encrypted.data(1)[0] + 1;
    	x_encrypted.data()[i] = x_encrypted.data()[i];
    		
    	decryptor.decrypt(x_encrypted, ans);
    	count_queries = count_queries + 1;
    		
    	if(ans.data()[i] == ans_correct)//perturbation had no effect
    	{
		generated_key = fopen("generated_key.txt","a");
        	fprintf(generated_key, "%d ", 0);
        	fclose(generated_key);

    	}
	else//perturbation caused result to flip
	{
		reactions = reactions + 1;
		x = rand() % 4;
    		y = rand() % 4;
    	
    		data_points = fopen("data_points.csv", "a");
    		fprintf(data_points, "%ld,%ld\n", x, y);
    		fclose(data_points);
    
    		Plaintext x_plain(uint64_to_hex_string(x));
    		Plaintext y_plain(uint64_to_hex_string(y));
		
		encryptor.encrypt(x_plain, x_encrypted);
    		encryptor.encrypt(y_plain, y_encrypted);
    	
    		evaluator.add_inplace(x_encrypted, y_encrypted);
    		
		decryptor.decrypt(x_encrypted, ans_original);
		
		ans_correct = ans_original.data()[i];
  		
    		x_encrypted.data(1)[0] = x_encrypted.data(1)[0] + 1;
    		x_encrypted.data()[i] = x_encrypted.data()[i] + 1;
    		
    		decryptor.decrypt(x_encrypted, ans);
    		count_queries = count_queries + 1;
    		
    		if(ans.data()[i] == ans_correct)//perturbation had no effect
    		{
			generated_key = fopen("generated_key.txt","a");
        		fprintf(generated_key, "%d ", -1);
        		fclose(generated_key);
    		}
    		else
    		{
    			reactions = reactions + 1;
    			
    			generated_key = fopen("generated_key.txt","a");
        		fprintf(generated_key, "%d ", 1);
        		fclose(generated_key);
    		}
	}
    	
    	FILE* count_of_oracle_accesses = fopen("count_of_oracle_accesses.csv","a");
    	fprintf(count_of_oracle_accesses, "%d\n", count_queries);
    	fclose(count_of_oracle_accesses);
	
    }
    cout << "No. of reactions: " << reactions << "\n" << endl;
}
