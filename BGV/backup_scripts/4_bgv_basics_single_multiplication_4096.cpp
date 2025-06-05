// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"

using namespace std;
using namespace seal;

void example_bgv_basics()
{
    print_example_banner("Example: BGV Basics");

    EncryptionParameters parms(scheme_type::bgv);
    size_t poly_modulus_degree = 4096;
    parms.set_poly_modulus_degree(poly_modulus_degree);

    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    
    parms.set_plain_modulus(1024);
    
    SEALContext context(parms);

    /*print_line(__LINE__);
    cout << "Set encryption parameters and print" << endl;
    print_parameters(context);*/

    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    
    /*PublicKey public_key;
    keygen.create_public_key(public_key);*/
    
    uint64_t q = 68719403009;
    
    uint64_t neg_threshold = 34359808000;
    uint64_t pos_threshold = 34359808000;
    
    uint64_t x = 1;
    uint64_t y = 2;
    
    Plaintext x_plain(uint64_to_hex_string(x));
    Plaintext y_plain(uint64_to_hex_string(y));

    Encryptor encryptor(context, secret_key);

    Evaluator evaluator(context);

    Decryptor decryptor(context, secret_key);
    
    Ciphertext x_encrypted;
    Ciphertext y_encrypted;
    
    Plaintext decrypted_x_times_y;
    
    for(int i = 0; i <= 10; ++i)
    {
    	encryptor.encrypt(x_plain, x_encrypted);
    	encryptor.encrypt(y_plain, y_encrypted);
    	
    	evaluator.add_inplace(x_encrypted, y_encrypted);
    
    	//x_encrypted.data(1)[0] = x_encrypted.data(1)[0];
    	//x_encrypted.data()[0] = x_encrypted.data()[0] + pos_threshold;
    		
    	decryptor.decrypt(x_encrypted, decrypted_x_times_y);
    
    	cout << "0x" << decrypted_x_times_y.to_string() << " ...... Correct." << endl;
    }
    
}
