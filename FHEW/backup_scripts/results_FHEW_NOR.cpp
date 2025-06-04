#include <iostream>
#include <cstdlib>
#include<string.h>
#include<stdlib.h>
#include "LWE.h"
#include "FHEW.h"
#include "distrib.h"

using namespace std;

void help(char* cmd) {
  cerr << "\nusage: " << cmd << " n\n\n" 
  << "  Generate a secret key sk and evaluation key ek, and repeat the following test n times:\n"
  << "   - generate random bits b1,b2,b3,b4\n"
  << "   - compute ciphertexts c1, c2, c3 and c4 encrypting b1, b2, b3 and b4  under sk\n"
  << "   - homomorphically compute the encrypted (c1 NAND c2) NAND (c3 NAND c4) \n"
  << "   - decrypt all the intermediate results and check correctness \n"
  << "\n If any of the tests fails, print ERROR and stop immediately.\n\n";
  exit(0);
}

int cleartext_gate(int v1, int v2, BinGate gate){
  switch(gate)
  {
    case OR: return v1 || v2;
    case AND: return v1 && v2;
    case NOR: return not(v1 || v2);
    case NAND: return not(v1 && v2);
    default: cerr << "\n This gate does not exists \n"; exit(1); return 0;
  }
}

void cerr_gate(BinGate gate){
  switch(gate)
  {
    case OR: cerr << " OR\t"; return;
    case AND: cerr << " AND\t"; return;
    case NOR: cerr << " NOR\t"; return;
    case NAND: cerr << " NAND\t"; return;
  }
}

int neg_threshold = 32;
int pos_threshold = 31;

int count;
int no_of_attempts = 11;
int reactions = 0;

LWE::SecretKey LWEsk;
FHEW::EvalKey EK;
LWE::CipherText e1, e2, e12;

void get_ciphertexts()
{
	int v1,v2;
  	v1 = rand()%2;
  	v2 = rand()%2;
  
  	LWE::Encrypt(&e1, LWEsk, v1);
  	LWE::Encrypt(&e2, LWEsk, v2);
  
  	BinGate gate = static_cast<BinGate>(2);
  	FHEW::HomGate(&e12, gate, EK, e1, e2);
}

void get_s_j(int j)
{
	FILE *generated_key;
	int ans_original, ans_incorrect, ans;
	for(int i = 1; i <= no_of_attempts; ++i)
	{
		get_ciphertexts();
		ans_original = LWE::Decrypt(LWEsk, e12);
		
		if(ans_original == 0)
    		{
    			ans_incorrect = 3;
    		}
    		else if(ans_original == 1)
    		{
    			ans_incorrect = 0;
    		}
    		
    		e12.a[j] = e12.a[j] + 32;
    		e12.b = e12.b - neg_threshold;
    		ans = LWE::Decrypt(LWEsk, e12);
    		count = count + 1;
    		
    		//cout << ans << endl;
    		
    		if(ans == ans_incorrect)//perturbation causes result to flip
    		{
			generated_key = fopen("generated_key.txt","a");
        		fprintf(generated_key, "%d ", 1);
        		fclose(generated_key);
        		reactions = reactions + 1;
        		return;
    		}
	}
	for(int i = 1; i <= no_of_attempts; ++i)
	{
		get_ciphertexts();
		ans_original = LWE::Decrypt(LWEsk, e12);
		
		if(ans_original == 0)
    		{
    			ans_incorrect = 1;
    		}
    		else if(ans_original == 1)
    		{
    			ans_incorrect = 2;
    		}
    		
    		e12.a[j] = e12.a[j] + 32;
    		e12.b = e12.b + pos_threshold;
    		ans = LWE::Decrypt(LWEsk, e12);
    		count = count + 1;
    		
    		//cout << ans << endl;
    		
    		if(ans == ans_incorrect)//perturbation causes result to flip
    		{
			generated_key = fopen("generated_key.txt","a");
        		fprintf(generated_key, "%d ", -1);
        		fclose(generated_key);
        		reactions = reactions + 1;
        		return;
    		}
	}
	generated_key = fopen("generated_key.txt","a");
        fprintf(generated_key, "%d ", 0);
        fclose(generated_key);
	
}

int main(int argc, char *argv[]) {

  	srand(967); //srand(967); srand(1073); srand(2512); srand(2406); srand(2022); for testing.

  	cerr << "Setting up FHEW \n";
  	FHEW::Setup();
  	cerr << "Generating secret key ... ";
  
  	LWE::KeyGen(LWEsk);
  
  	FILE *secret_key = fopen("secret_key.txt","a");
  	for(int i = 0; i < n; ++i) {
    		fprintf(secret_key, "%d ", LWEsk[i]);
  	}
  	fprintf(secret_key, "\n");
  	fclose(secret_key);
  
  	cerr << " Done.\n";
  	cerr << "Generating evaluation key ... this may take a while ... ";
  
  	FHEW::KeyGen(&EK, LWEsk);
  	cerr << " Done.\n\n";

  	for(int i = 0; i < 500; i++) {

    		count = 0;
    		cerr << "Retrieving s[" << i << "]" << endl;
    		get_s_j(i);
    		FILE* count_of_oracle_accesses = fopen("count_of_oracle_accesses.csv","a");
    		fprintf(count_of_oracle_accesses, "%d\n", count);
    		fclose(count_of_oracle_accesses);
    		
    	}
    	cerr << "No. of reactions: " << reactions << "\n" << endl;
}


