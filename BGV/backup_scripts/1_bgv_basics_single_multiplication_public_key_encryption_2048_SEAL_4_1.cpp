// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"

using namespace std;
using namespace seal;

uint64_t q = 18014398492704769;

uint64_t neg_threshold = 4503599623177216;//9007199246353408;
uint64_t pos_threshold = 4503599623176192;//9007199246352384;

int count_queries;
int no_of_attempts = 20;
int reactions = 0;

void example_bgv_basics()
{

    srand(967); //srand(967); srand(1073); srand(2512); srand(2406); srand(2022); for testing.
    
    print_example_banner("Example: BGV Basics");

    EncryptionParameters parms(scheme_type::bgv);

    size_t poly_modulus_degree = 2048;
    parms.set_poly_modulus_degree(poly_modulus_degree);

    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));

    parms.set_plain_modulus(1024);

    SEALContext context(parms);

    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    
    PublicKey public_key;
    keygen.create_public_key(public_key);
    
    auto &context_data = *context.key_context_data();
    auto ntt_tables = context_data.small_ntt_tables();
    
    auto &coeff_modulus = parms.coeff_modulus();
    size_t coeff_modulus_size = coeff_modulus.size();
    
    uint64_t x;
    uint64_t y;

    Encryptor encryptor(context, public_key);

    Evaluator evaluator(context);

    Decryptor decryptor(context, secret_key);
    
    Ciphertext x_encrypted;
    Ciphertext y_encrypted;
    
    Ciphertext temp_ctxt;
    
    //Server chooses one of the client's ciphertext at random, makes a copy of it and then use it for manipulation
    Plaintext temp_ptxt(uint64_to_hex_string(1));
    
    encryptor.encrypt(temp_ptxt, temp_ctxt);
    
    Plaintext ans_original, ans;
    
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
		
		x = rand() % 8;
    		y = rand() % 8;
    	
    		data_points = fopen("data_points.csv", "a");
    		fprintf(data_points, "%ld,%ld\n", x, y);
    		fclose(data_points);
    
    		Plaintext x_plain(uint64_to_hex_string(x));
    		Plaintext y_plain(uint64_to_hex_string(y));
		
		encryptor.encrypt(x_plain, x_encrypted);
    		encryptor.encrypt(y_plain, y_encrypted);
    	
    		evaluator.multiply_inplace(x_encrypted, y_encrypted);
    		
		decryptor.decrypt(x_encrypted, ans_original);
		
		for(int i = 0; i < poly_modulus_degree; ++i)
    		{
        		temp_ctxt.data(1)[i] = 0;
        		temp_ctxt.data()[i] = 0;
    		}
    
    		temp_ctxt.data(1)[0] = (temp_ctxt.data(1)[0] + 4503599623176192) % q;
    		
    		temp_ctxt.data()[i] = (temp_ctxt.data()[i] + pos_threshold) % q;
   		
    		uint64_t *c0 = temp_ctxt.data();
            	uint64_t *c1 = temp_ctxt.data(1);
    		
    		for(int j = 0; j < coeff_modulus_size; ++j)
    		{
    			ntt_negacyclic_harvey(c0 + j * poly_modulus_degree, ntt_tables[j]);
    			ntt_negacyclic_harvey(c1 + j * poly_modulus_degree, ntt_tables[j]);
    		}
  		
    		evaluator.add_inplace(x_encrypted, temp_ctxt);
    		
    		decryptor.decrypt(x_encrypted, ans);
    		count_queries = count_queries + 1;
    		cout << "ans_original: 0x" << ans_original.to_string() << " ans: 0x" << ans.to_string() << endl;
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
		
		x = rand() % 8;
    		y = rand() % 8;
    	
    		data_points = fopen("data_points.csv", "a");
    		fprintf(data_points, "%ld,%ld\n", x, y);
    		fclose(data_points);
    
    		Plaintext x_plain(uint64_to_hex_string(x));
    		Plaintext y_plain(uint64_to_hex_string(y));
		
		encryptor.encrypt(x_plain, x_encrypted);
    		encryptor.encrypt(y_plain, y_encrypted);
    	
    		evaluator.multiply_inplace(x_encrypted, y_encrypted);
    		
		decryptor.decrypt(x_encrypted, ans_original);

		for(int i = 0; i < poly_modulus_degree; ++i)
    		{
        		temp_ctxt.data(1)[i] = 0;
        		temp_ctxt.data()[i] = 0;
    		}
    
    		temp_ctxt.data(1)[0] = (temp_ctxt.data(1)[0] + 4503599623176192) % q;
    		
    		temp_ctxt.data()[i] = (temp_ctxt.data()[i] - neg_threshold) % q;
  		
    		uint64_t *c0 = temp_ctxt.data();
            	uint64_t *c1 = temp_ctxt.data(1);
    		
    		for(int j = 0; j < coeff_modulus_size; ++j)
    		{
    			ntt_negacyclic_harvey(c0 + j * poly_modulus_degree, ntt_tables[j]);
    			ntt_negacyclic_harvey(c1 + j * poly_modulus_degree, ntt_tables[j]);
    		}
 
    		evaluator.add_inplace(x_encrypted, temp_ctxt);
   		
    		decryptor.decrypt(x_encrypted, ans);
    		count_queries = count_queries + 1;
    		cout << "ans_original: 0x" << ans_original.to_string() << " ans: 0x" << ans.to_string() << endl;
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
