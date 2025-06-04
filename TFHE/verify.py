def convert(str_lst):
	lst = []
	for string in str_lst:
		if (string != ""):
			temp = int(string)
			lst.append(temp)
	return lst
	
with open('generated_key.txt', 'r') as fp:
	lines = fp.readlines()
	temp = lines[0].strip().split(" ")
	gk = convert(temp)
	
with open('secret_key.txt', 'r') as fp:
	lines = fp.readlines()
	temp = lines[0].strip().split(" ")
	sk = convert(temp)
	
n = 630 #key size
no_of_queries = 0 #Counts number of queries made to the conditional decryption oracle
no_of_nonzero_key_bits = 0

for i in range(n):
	if(gk[i] != sk[i]):
		print("Mismatch in bit: " + str(i + 1) + "\n")
	if(sk[i] != 0):
		no_of_nonzero_key_bits = no_of_nonzero_key_bits + 1
		
print("Number of non-zero secret key bits: " + str(no_of_nonzero_key_bits))
		
with open('Number_of_decryptions.csv', 'r') as fp:
	lines = fp.readlines()
	for line in lines:
		no_of_queries = no_of_queries + int(line.strip())
		
print("Total number of queries made to the conditional decryption oracle: " + str(no_of_queries))
