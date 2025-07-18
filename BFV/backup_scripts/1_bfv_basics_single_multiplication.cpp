// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"

using namespace std;
using namespace seal;

void example_bfv_basics()
{
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
    
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    
    uint64_t x = 1;
    uint64_t y = 2;
    
    Plaintext x_plain(uint64_to_hex_string(x));
    Plaintext y_plain(uint64_to_hex_string(y));

    Encryptor encryptor(context, secret_key);

    Evaluator evaluator(context);

    Decryptor decryptor(context, secret_key);
    
    Ciphertext x_encrypted;
    Ciphertext y_encrypted;
    
    Ciphertext x_times_y;
    
    Plaintext decrypted_x_times_y;
    
    //FILE *test;
    
    for(int i = 0; i <= 10; ++i)
    {
    	encryptor.encrypt(x_plain, x_encrypted);
    	encryptor.encrypt(y_plain, y_encrypted);
    	
    	evaluator.multiply(x_encrypted, y_encrypted, x_times_y);
    	evaluator.relinearize_inplace(x_times_y, relin_keys);
    		
    	decryptor.decrypt(x_times_y, decrypted_x_times_y);
    
    	cout << "0x" << decrypted_x_times_y.to_string() << " ...... Correct." << endl;
    
    	x_times_y.data(1)[0] = x_times_y.data(1)[0] + 105;
    	//x_times_y.data()[0] = x_times_y.data()[0];
    
    	decryptor.decrypt(x_times_y, decrypted_x_times_y);
    
    	cout << "0x" << decrypted_x_times_y.to_string() << endl;
    	
    	/*test = fopen("test.csv","a");
    	fprintf(test, "%d,%ld\n", i, decrypted_x_times_y.data()[1]);
    	fclose(test);*/
    }
    
}
