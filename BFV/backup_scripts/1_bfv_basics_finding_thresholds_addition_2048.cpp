// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"

using namespace std;
using namespace seal;

void example_bfv_basics()
{
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
    
    uint64_t x = 5;
    uint64_t y = 10;
    
    Plaintext x_plain(uint64_to_hex_string(x));
    Plaintext y_plain(uint64_to_hex_string(y));

    Encryptor encryptor(context, secret_key);

    Evaluator evaluator(context);

    Decryptor decryptor(context, secret_key);
    
    Ciphertext x_encrypted;
    Ciphertext y_encrypted;
    
    Plaintext decrypted_x_times_y;
    
    encryptor.encrypt(x_plain, x_encrypted);
    encryptor.encrypt(y_plain, y_encrypted);
    	
    evaluator.add_inplace(x_encrypted, y_encrypted);
    
    uint64_t l = 1000000000000;
    uint64_t r = 9000000000000;
    
    uint64_t e_th = 0;
    
    while(l <= r)
    {
    	uint64_t mid = l + ((r - l) / 2);
    	
    	x_encrypted.data()[0] = x_encrypted.data()[0] + mid;
    	
    	decryptor.decrypt(x_encrypted, decrypted_x_times_y);
    	
    	x_encrypted.data()[0] = x_encrypted.data()[0] - mid;
    	
    	uint64_t ans = decrypted_x_times_y.data()[0];
    	
    	if(ans == 15)
    	{
    		e_th = mid;
    		l = mid + 1;
    	}
    	else if(ans == 16)
    	{
    		r = mid - 1;
    	}
    }
    
    cout << e_th << endl;
    
}
