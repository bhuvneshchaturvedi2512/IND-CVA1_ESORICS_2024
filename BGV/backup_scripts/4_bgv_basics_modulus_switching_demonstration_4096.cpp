// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"

using namespace std;
using namespace seal;

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
    
    PublicKey public_key;
    keygen.create_public_key(public_key);
    
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    
    uint64_t x;
    uint64_t y;

    Encryptor encryptor(context, public_key);

    Evaluator evaluator(context);

    Decryptor decryptor(context, secret_key);
    
    Ciphertext x_encrypted;
    Ciphertext y_encrypted;
    Ciphertext x_times_y;
    Ciphertext x_times_y_next;
    
    Plaintext ans_original;

    x = rand() % 4;
    y = rand() % 4;
    
    Plaintext x_plain(uint64_to_hex_string(x));
    Plaintext y_plain(uint64_to_hex_string(y));
		
    encryptor.encrypt(x_plain, x_encrypted);
    encryptor.encrypt(y_plain, y_encrypted);
    	
    evaluator.multiply(x_encrypted, y_encrypted, x_times_y);
    
    auto &context_data_before_mod_switching = *context.get_context_data(x_times_y.parms_id());
    auto &params_before_mod_switching = context_data_before_mod_switching.parms();
    auto &coeff_modulus_before_mod_switching = params_before_mod_switching.coeff_modulus();
    size_t coeff_count_before_mod_switching = params_before_mod_switching.poly_modulus_degree();
    size_t coeff_modulus_size_before_mod_switching = coeff_modulus_before_mod_switching.size();
    cout << "values of q before modulus switching: " << endl;
    for (size_t i = 0; i < coeff_modulus_size_before_mod_switching; i++)
    {
        cout << coeff_modulus_before_mod_switching[i].value() << endl;
    }
    
    evaluator.relinearize_inplace(x_times_y, relin_keys);
    evaluator.mod_switch_to_next(x_times_y, x_times_y_next);
    
    auto &context_data_after_mod_switching = *context.get_context_data(x_times_y_next.parms_id());
    auto &params_after_mod_switching = context_data_after_mod_switching.parms();
    auto &coeff_modulus_after_mod_switching = params_after_mod_switching.coeff_modulus();
    size_t coeff_count_after_mod_switching = params_after_mod_switching.poly_modulus_degree();
    size_t coeff_modulus_size_after_mod_switching = coeff_modulus_after_mod_switching.size();
    cout << "values of q after modulus switching: " << endl;
    for (size_t i = 0; i < coeff_modulus_size_after_mod_switching; i++)
    {
        cout << coeff_modulus_after_mod_switching[i].value() << endl;
    }
    		
    decryptor.decrypt(x_times_y_next, ans_original);
    
    cout << "x: " << x << " y: " << y <<" ans_original: 0x" << ans_original.to_string() << endl;

}
