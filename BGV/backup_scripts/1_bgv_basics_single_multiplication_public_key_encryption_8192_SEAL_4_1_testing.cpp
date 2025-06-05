// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"

using namespace std;
using namespace seal;

uint64_t q = 8727373455360;

uint64_t neg_threshold = 512000;
uint64_t pos_threshold = 512000;

void example_bgv_basics()
{

    srand(967); //srand(967); srand(1073); srand(2512); srand(2406); srand(2022); for testing.
    
    print_example_banner("Example: BGV Basics");

    EncryptionParameters parms(scheme_type::bgv);

    size_t poly_modulus_degree = 8192;
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
    Ciphertext x_times_y;
    Ciphertext x_times_y_next;
    
    Ciphertext temp_ctxt;
    Ciphertext temp_ctxt_next;
    
    //Server chooses one of the client's ciphertext at random, makes a copy of it and then use it for manipulation
    Plaintext temp_ptxt(uint64_to_hex_string(0));
    
    encryptor.encrypt(temp_ptxt, temp_ctxt);
    
    Plaintext ans_original, ans;
    
    x = rand() % 4;
    y = rand() % 4;
    
    Plaintext x_plain(uint64_to_hex_string(x));
    Plaintext y_plain(uint64_to_hex_string(y));
		
    encryptor.encrypt(x_plain, x_encrypted);
    encryptor.encrypt(y_plain, y_encrypted);
    	
    evaluator.multiply(x_encrypted, y_encrypted, x_times_y);
    evaluator.relinearize_inplace(x_times_y, relin_keys);
    evaluator.mod_switch_to_next(x_times_y, x_times_y_next);
    		
    decryptor.decrypt(x_times_y_next, ans_original);
    
    /*for(int i = 0; i < poly_modulus_degree; ++i)
    {
        temp_ctxt.data(1)[i] = 0;
        temp_ctxt.data()[i] = 0;
    }*/
    
    temp_ctxt.data(1)[0] = (temp_ctxt.data(1)[0] + neg_threshold) % q;
    		
    temp_ctxt.data()[0] = (temp_ctxt.data()[0] + pos_threshold) % q;
       		
    /*uint64_t *c0 = temp_ctxt.data();
    uint64_t *c1 = temp_ctxt.data(1);
    
    for(int j = 0; j < coeff_modulus_size; ++j)
    {
    	ntt_negacyclic_harvey(c0 + j * poly_modulus_degree, ntt_tables[j]);
    	ntt_negacyclic_harvey(c1 + j * poly_modulus_degree, ntt_tables[j]);
    }*/
        
    evaluator.mod_switch_to_next(temp_ctxt, temp_ctxt_next);
    
    evaluator.add_inplace(x_times_y_next, temp_ctxt_next);
    		
    decryptor.decrypt(x_times_y_next, ans);
    
    cout << "x: " << x << " y: " << y << " result (x*y): " << ans_original.to_string() << " result (x*y) after pert: " << ans.to_string() << endl;
    
}
