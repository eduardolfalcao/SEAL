//libs for reading csv
#include <iostream>
#include <fstream>
#include <vector>
#include <iterator>
#include <string>
#include <algorithm>
#include <boost/algorithm/string.hpp>

#include "../SEAL/native/examples/examples.h"
#include "seal/seal.h"
#include <iostream>

#include <typeinfo>
#include <unistd.h>

#include <chrono>
#include <thread>

using namespace std;
using namespace seal;

/*
 *  * A class to read data from a csv file.
 *   */
class CSVReader{
	std::string fileName;
	std::string delimeter;
			 
public:
	CSVReader(std::string filename, std::string delm = ",") :								fileName(filename), delimeter(delm)
	{ }

	// Function to fetch data from a CSV File
	std::vector<std::vector<std::string> > getData();
};

/*
 * Parses through csv file line by line and returns the data
 * in vector of vector of strings.
 */

std::vector<std::vector<std::string> > CSVReader::getData(){
	std::ifstream file(fileName);

	std::vector<std::vector<std::string> > dataList;

	std::string line = "";
	// Iterate through each line and split the content using delimeter
	getline(file, line);
	while (getline(file, line)){
		std::vector<std::string> vec;
		boost::algorithm::split(vec, line, boost::is_any_of(delimeter));
		dataList.push_back(vec);
	}

	// Close the File
	file.close();

	return dataList;	
}

EncryptionParameters createParameters(){

	/*EncryptionParameters parms(scheme_type::BFV);

	size_t poly_modulus_degree = 4096;
	parms.set_poly_modulus_degree(poly_modulus_degree);
	parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
	parms.set_plain_modulus(256);*/


    	EncryptionParameters parms(scheme_type::CKKS);

	size_t poly_modulus_degree = 32768;
    	parms.set_poly_modulus_degree(poly_modulus_degree);

	//amount of bits of prime: 60, 40, 40, 60
    	parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 40, 40, 40, 40, 40, 40, 60 }));

	return parms;
}


void decryptAndPrint(Decryptor* decryptor,CKKSEncoder* encoder,Ciphertext enc, string id){

	Plaintext plain_res;
	print_line(__LINE__);
	cout << "Decrypt and decode: " << id << "." << endl;
	decryptor->decrypt(enc, plain_res);
	vector<double> output;
	encoder->decode(plain_res, output);
	cout << "    + Result vector ...... Correct." << endl;
	print_vector(output, 4, 10);

}




Ciphertext g(Ciphertext x, Evaluator* evaluator, CKKSEncoder* encoder, Decryptor* decryptor, RelinKeys relin_keys, double scale, std::shared_ptr<SEALContext>* context){

	cout << "relin_keys: " << relin_keys.size() << endl;

	Ciphertext x1 = x;
	Ciphertext x2;
	evaluator->square(x1, x2);                                          
        evaluator->relinearize_inplace(x2, relin_keys);
	evaluator->rescale_to_next_inplace(x2);
	
	Ciphertext x3 = x2;

	cout << "    + Modulus chain index for x1: "
		<< (*context)->get_context_data(x1.parms_id())->chain_index() << endl;
	cout << "    + Modulus chain index for x3: "
		<< (*context)->get_context_data(x3.parms_id())->chain_index() << endl;
	
	parms_id_type last_parms_id = x2.parms_id();
	evaluator->mod_switch_to_inplace(x1, last_parms_id);	
	
	cout << "    + Modulus chain index for x1 after mod switch: "
		<< (*context)->get_context_data(x1.parms_id())->chain_index() << endl;
	cout << "    + Modulus chain index for x3 after mod switch: "
		<< (*context)->get_context_data(x3.parms_id())->chain_index() << endl;

	evaluator->multiply_inplace(x3,x1);
	evaluator->relinearize_inplace(x3, relin_keys);
	evaluator->rescale_to_next_inplace(x3);
	
	cout << "    ++++ Encrypted size of x3 = " << util::sub_safe(x3.size(),size_t(2)) << endl;

	Ciphertext x5 = x3;

	cout << "    + Modulus chain index for x2: "
		<< (*context)->get_context_data(x2.parms_id())->chain_index() << endl;
	cout << "    + Modulus chain index for x5: "
		<< (*context)->get_context_data(x5.parms_id())->chain_index() << endl;

	last_parms_id = x5.parms_id();
	evaluator->mod_switch_to_inplace(x2, last_parms_id);	

	cout << "    + Modulus chain index for x2 after mod switch: "
		<< (*context)->get_context_data(x2.parms_id())->chain_index() << endl;
	cout << "    + Modulus chain index for x5 after mod switch: "
		<< (*context)->get_context_data(x5.parms_id())->chain_index() << endl;

	evaluator->multiply_inplace(x5,x2);
	evaluator->relinearize_inplace(x5, relin_keys);
	evaluator->rescale_to_next_inplace(x5);

	
	cout << "    ++++ Encrypted size of x5 = " << util::sub_safe(x5.size(),size_t(2)) << endl;

	cout << "relin_keys: " << relin_keys.size() << endl;
	
	Ciphertext x7 = x5;

	cout << "    + Modulus chain index for x2: "
		<< (*context)->get_context_data(x2.parms_id())->chain_index() << endl;
	cout << "    + Modulus chain index for x7: "
		<< (*context)->get_context_data(x7.parms_id())->chain_index() << endl;

	last_parms_id = x5.parms_id();
	evaluator->mod_switch_to_inplace(x2, last_parms_id);	

	cout << "    + Modulus chain index for x2 after mod switch: "
		<< (*context)->get_context_data(x2.parms_id())->chain_index() << endl;
	cout << "    + Modulus chain index for x7 after mod switch: "
		<< (*context)->get_context_data(x7.parms_id())->chain_index() << endl;

	evaluator->multiply_inplace(x7,x2);
	evaluator->relinearize_inplace(x7, relin_keys);
	evaluator->rescale_to_next_inplace(x7);

	cout << "    ++++ Encrypted size of x7 = " << util::sub_safe(x7.size(),size_t(2)) << endl;

	Ciphertext x9 = x7;

	cout << "    + Modulus chain index for x2: "
		<< (*context)->get_context_data(x2.parms_id())->chain_index() << endl;
	cout << "    + Modulus chain index for x9: "
		<< (*context)->get_context_data(x9.parms_id())->chain_index() << endl;

	last_parms_id = x9.parms_id();
	evaluator->mod_switch_to_inplace(x2, last_parms_id);	

	cout << "    + Modulus chain index for x2 after mod switch: "
		<< (*context)->get_context_data(x2.parms_id())->chain_index() << endl;
	cout << "    + Modulus chain index for x9 after mod switch: "
		<< (*context)->get_context_data(x9.parms_id())->chain_index() << endl;


	cout << "    ++++ Encrypted size of x9 = " << util::sub_safe(x9.size(),size_t(2)) << endl;

	evaluator->multiply_inplace(x9,x2);

	cout << "    ++++ Encrypted size of x9 = " << util::sub_safe(x9.size(),size_t(2)) << endl;

	evaluator->relinearize_inplace(x2, relin_keys);
	evaluator->relinearize_inplace(x9, relin_keys);
	evaluator->rescale_to_next_inplace(x9);


	/*double w0 = 0.5;
	double w1 = 0.2159198015;
	double w3 = -0.0082176259;
	double w5 = 0.0001825597;
	double w7 = -0.0000018848;
	double w9 = 0.0000000072;*/

	Plaintext w0_plain, w1_plain, w3_plain, w5_plain, w7_plain, w9_plain;
	encoder->encode(0.5, scale, w0_plain);
	encoder->encode(0.2159198015, scale, w1_plain);
	encoder->encode(-0.0082176259, scale, w3_plain);
	encoder->encode(0.0001825597, scale, w5_plain);
	encoder->encode(-0.0000018848, scale, w7_plain);
	encoder->encode(0.0000000072, scale, w9_plain);

	
	Ciphertext y1 = x1;

	cout << "    + Modulus chain index for x1: "
		<< (*context)->get_context_data(x1.parms_id())->chain_index() << endl;
	cout << "    + Modulus chain index for w1_plain: "
		<< (*context)->get_context_data(w1_plain.parms_id())->chain_index() << endl;

	last_parms_id = x1.parms_id();
	evaluator->mod_switch_to_inplace(w1_plain, last_parms_id);	

	evaluator->multiply_plain_inplace(y1,w1_plain);
	evaluator->relinearize_inplace(y1, relin_keys);
	evaluator->rescale_to_next_inplace(y1);
	decryptAndPrint(decryptor,encoder,y1,"y1");

	
	Ciphertext y3 = x3;

	cout << "    + Modulus chain index for x3: "
		<< (*context)->get_context_data(x3.parms_id())->chain_index() << endl;
	cout << "    + Modulus chain index for w3_plain: "
		<< (*context)->get_context_data(w3_plain.parms_id())->chain_index() << endl;

	last_parms_id = x3.parms_id();
	evaluator->mod_switch_to_inplace(w3_plain, last_parms_id);	

	evaluator->multiply_plain_inplace(y3,w3_plain);
	evaluator->relinearize_inplace(y3, relin_keys);
	evaluator->rescale_to_next_inplace(y3);
	decryptAndPrint(decryptor,encoder,y3,"y3");


	Ciphertext y5 = x5;

	cout << "    + Modulus chain index for x5: "
		<< (*context)->get_context_data(x5.parms_id())->chain_index() << endl;
	cout << "    + Modulus chain index for w5_plain: "
		<< (*context)->get_context_data(w5_plain.parms_id())->chain_index() << endl;

	last_parms_id = x5.parms_id();
	evaluator->mod_switch_to_inplace(w5_plain, last_parms_id);	

	evaluator->multiply_plain_inplace(y5,w5_plain);
	evaluator->relinearize_inplace(y5, relin_keys);
	evaluator->rescale_to_next_inplace(y5);
	decryptAndPrint(decryptor,encoder,y5,"y5");


	Ciphertext y7 = x7;

	cout << "    + Modulus chain index for x7: "
		<< (*context)->get_context_data(x7.parms_id())->chain_index() << endl;
	cout << "    + Modulus chain index for w7_plain: "
		<< (*context)->get_context_data(w7_plain.parms_id())->chain_index() << endl;

	last_parms_id = x7.parms_id();
	evaluator->mod_switch_to_inplace(w7_plain, last_parms_id);	

	evaluator->multiply_plain_inplace(y7,w7_plain);
	evaluator->relinearize_inplace(y7, relin_keys);
	decryptAndPrint(decryptor,encoder,y7,"y7");
	evaluator->rescale_to_next_inplace(y7);


	Ciphertext y9 = x9;

	cout << "    + Modulus chain index for x9: "
		<< (*context)->get_context_data(x9.parms_id())->chain_index() << endl;
	cout << "    + Modulus chain index for w9_plain: "
		<< (*context)->get_context_data(w9_plain.parms_id())->chain_index() << endl;

	last_parms_id = x9.parms_id();
	evaluator->mod_switch_to_inplace(w9_plain, last_parms_id);	

	evaluator->multiply_plain_inplace(y9,w9_plain);
	evaluator->relinearize_inplace(y9, relin_keys);
	decryptAndPrint(decryptor,encoder,y9,"y9");
	evaluator->rescale_to_next_inplace(y9);

	
	cout << "relin_keys: " << relin_keys.size() << endl;


	cout << "    +++++ Modulus chain index for y9: "
		<< (*context)->get_context_data(y9.parms_id())->chain_index() << endl;
	cout << "    +++++ Modulus chain index for y7: "
		<< (*context)->get_context_data(y7.parms_id())->chain_index() << endl;	
	cout << "    +++++ Modulus chain index for y5: "
		<< (*context)->get_context_data(y5.parms_id())->chain_index() << endl;
	cout << "    +++++ Modulus chain index for y3: "
		<< (*context)->get_context_data(y3.parms_id())->chain_index() << endl;
	cout << "    +++++ Modulus chain index for y1: "
		<< (*context)->get_context_data(y1.parms_id())->chain_index() << endl;

	last_parms_id = y9.parms_id();
	evaluator->mod_switch_to_inplace(y7, last_parms_id);
	evaluator->mod_switch_to_inplace(y5, last_parms_id);
	evaluator->mod_switch_to_inplace(y3, last_parms_id);
	evaluator->mod_switch_to_inplace(y1, last_parms_id);


	cout << "    +++++ Modulus chain index for y9 after mod switch: "
		<< (*context)->get_context_data(y9.parms_id())->chain_index() << endl;
	cout << "    +++++ Modulus chain index for y7 after mod switch: "
		<< (*context)->get_context_data(y7.parms_id())->chain_index() << endl;	
	cout << "    +++++ Modulus chain index for y5 after mod switch: "
		<< (*context)->get_context_data(y5.parms_id())->chain_index() << endl;
	cout << "    +++++ Modulus chain index for y3 after mod switch: "
		<< (*context)->get_context_data(y3.parms_id())->chain_index() << endl;
	cout << "    +++++ Modulus chain index for y1 after mod switch: "
		<< (*context)->get_context_data(y1.parms_id())->chain_index() << endl;


	//cout << fixed << setprecision(10);

	cout <<	"y9 and y7 are in the same scale? " << util::are_close<double>(y9.scale(), y7.scale()) << endl;
	cout <<	"y9 scale: " << y9.scale() << endl;
	cout <<	"y7 scale: " << y7.scale() << endl;
	cout <<	"y5 scale: " << y5.scale() << endl;
	cout <<	"y3 scale: " << y3.scale() << endl;
	cout <<	"y1 scale: " << y1.scale() << endl;

	cout << "pow(2.0, 40) = " << pow(2.0, 40) << endl;

	y9.scale() = pow(2.0, 40);
	y7.scale() = pow(2.0, 40);
	y5.scale() = pow(2.0, 40);
	y3.scale() = pow(2.0, 40);
	y1.scale() = pow(2.0, 40);

	cout <<	"y9 scale after change scaling: " << y9.scale() << endl;
	cout <<	"y7 scale after change scaling: " << y7.scale() << endl;
	cout <<	"y5 scale after change scaling: " << y5.scale() << endl;
	cout <<	"y3 scale after change scaling: " << y3.scale() << endl;
	cout <<	"y1 scale after change scaling: " << y1.scale() << endl;
	

	Ciphertext z;
	std::vector<Ciphertext> factors;
	factors.push_back(y9);
	factors.push_back(y7);
	factors.push_back(y5);
	factors.push_back(y3);
	factors.push_back(y1);

	evaluator->add_many(factors,z);
	evaluator->relinearize_inplace(z, relin_keys);
	//evaluator->rescale_to_next_inplace(z);
	
	decryptAndPrint(decryptor,encoder,z,"z");

	
	cout << "    +++++ Modulus chain index for z: "
		<< (*context)->get_context_data(z.parms_id())->chain_index() << endl;
	cout << "    +++++ Modulus chain index for w0_plain: "
		<< (*context)->get_context_data(w0_plain.parms_id())->chain_index() << endl;
	last_parms_id = z.parms_id();
	evaluator->mod_switch_to_inplace(w0_plain, last_parms_id);
	cout << "    +++++ Modulus chain index for w0_plain after mod switch: "
		<< (*context)->get_context_data(w0_plain.parms_id())->chain_index() << endl;

	cout <<	"z and w0_plain are in the same scale? " << util::are_close<double>(z.scale(), w0_plain.scale()) << endl;
	cout <<	"z scale: " << z.scale() << endl;
	cout <<	"w0_plain scale: " << w0_plain.scale() << endl;

	z.scale() = pow(2.0, 40);

	cout <<	"z scale: " << z.scale() << endl;
	cout <<	"w0_plain scale: " << w0_plain.scale() << endl;

	evaluator->add_plain_inplace(z,w0_plain);

	return z;
}



Ciphertext h(vector<Ciphertext> x, Ciphertext theta, Evaluator* evaluator, CKKSEncoder* encoder, Decryptor* decryptor, RelinKeys relin_keys, double scale, std::shared_ptr<SEALContext>* context){

	cout << "relin_keys: " << relin_keys.size() << endl;

	Ciphertext x1 = x;
	Ciphertext x2;

}


int main(){

	EncryptionParameters parms = createParameters();
	
	auto context = SEALContext::Create(parms);
	print_line(__LINE__);
	cout << "Set encryption parameters and print" << endl;
	print_parameters(context);
	cout << endl;

    	KeyGenerator keygen(context);
    	auto public_key = keygen.public_key();
    	auto secret_key = keygen.secret_key();
    	auto relin_keys = keygen.relin_keys();

	Encryptor encryptor(context, public_key);
	Evaluator evaluator(context);
    	Decryptor decryptor(context, secret_key);

    	CKKSEncoder encoder(context);

    	size_t slot_count = encoder.slot_count();
    	cout << "Number of slots: " << slot_count << endl;

	double scale = pow(2.0, 40);

	print_line(__LINE__);
	vector<double> input{ -0.5 };
	cout << "Input vector: " << endl;
	print_vector(input);

	Plaintext plain;
	print_line(__LINE__);
	cout << "Encode input vector." << endl;
	encoder.encode(input, scale, plain);

	Ciphertext encrypted;
	print_line(__LINE__);
	cout << "Encrypt input vector and square." << endl;
	encryptor.encrypt(plain, encrypted);

	Ciphertext enc_sq = g(encrypted, &evaluator, &encoder,&decryptor, relin_keys, scale, &context);


	//evaluator).rescale_to_next_inplace(x1);	

	/*evaluator.multiply_inplace(x3,x1);
	evaluator.relinearize_inplace(x3, relin_keys);
	evaluator.rescale_to_next_inplace(x3);*/

	Plaintext plain_res;
	print_line(__LINE__);
	cout << "Decrypt and decode." << endl;
	decryptor.decrypt(enc_sq, plain_res);
	vector<double> output;
	encoder.decode(plain_res, output);
	cout << "    + Result vector ...... Correct." << endl;
	print_vector(output, 4, 10);

	/*vector<double> output;
	cout << "    + Decode input vector ...... Correct." << endl;
	encoder.decode(plain, output);
	print_vector(output);

	Ciphertext encrypted;
	print_line(__LINE__);
	cout << "Encrypt input vector, square, and relinearize." << endl;
	encryptor.encrypt(plain, encrypted);

	evaluator.square_inplace(encrypted);
	evaluator.relinearize_inplace(encrypted, relin_keys);

	Plaintext plain_float;
	encoder.encode(3.5, scale, plain_float);
	evaluator.multiply_plain_inplace(encrypted,plain_float);	
	evaluator.relinearize_inplace(encrypted, relin_keys);

	cout << "    + Scale in squared input: " << encrypted.scale()
		        << " (" << log2(encrypted.scale()) << " bits)" << endl;

	print_line(__LINE__);
	cout << "Decrypt and decode." << endl;
	decryptor.decrypt(encrypted, plain);
	encoder.decode(plain, output);
	cout << "    + Result vector ...... Correct." << endl;
	print_vector(output);*/


	/*
	// Creating an object of CSVWriter
	CSVReader reader("mimic10lines.csv");

	// Get the data from CSV File
	std::vector<std::vector<std::string> > dataList = reader.getData();	
	// each Ciphertext contains a vector of values
	std::vector<Ciphertext> encryptedMatrix; 
	// Print the content of row by row on screen
	for(std::vector<std::string> vec : dataList){
		vector<double> line;
		for(std::string data : vec){	
			double v = atof(data.c_str());
			line.push_back(v);
			std::cout<< v << ", ";
		}
		Plaintext plain;
		encoder.encode(line, scale, plain);
		Ciphertext encrypted;
		encryptor.encrypt(plain, encrypted);
		encryptedMatrix.push_back(encrypted);
		std::cout<<std::endl;
	}

	std::cout << " Decrypting! " << std::endl << std::endl;
	for(Ciphertext encrypted : encryptedMatrix){
		//for(Ciphertext encrypted : encryptedVector){				
		Plaintext plain_result;
		decryptor.decrypt(encrypted, plain_result);
		vector<double> output;
		encoder.decode(plain_result, output);
		cout << output.size() << std::endl;
		print_vector(output,8,3);
	}*/




    	/*
	    We create a small vector to encode; the CKKSEncoder will implicitly pad it
	    with zeros to full size (poly_modulus_degree / 2) when encoding.
	    */
	/*vector<double> input{ 0.0, 1.1, 2.2, 3.3 };
    	cout << "Input vector: " << endl;
    	print_vector(input);*/

    	/*
	    Now we encode it with CKKSEncoder. The floating-point coefficients of `input'
	    will be scaled up by the parameter `scale'. This is necessary since even in
	    the CKKS scheme the plaintext elements are fundamentally polynomials with
	    integer coefficients. It is instructive to think of the scale as determining
	    the bit-precision of the encoding; naturally it will affect the precision of
	    the result.

	    In CKKS the message is stored modulo coeff_modulus (in BFV it is stored modulo
	    plain_modulus), so the scaled message must not get too close to the total size
	    of coeff_modulus. In this case our coeff_modulus is quite large (218 bits) so
	    we have little to worry about in this regard. For this simple example a 30-bit
	    scale is more than enough.
	    */

    	/*
	 *     We can instantly decode to check the correctness of encoding.
	 *      */
	/*vector<double> output;
    	cout << "    + Decode input vector ...... Correct." << endl;
    	encoder.decode(plain, output);
    	print_vector(output);*/


	/*
	print_line(__LINE__);
	int x = 6;
	Plaintext x_plain(to_string(x));
	cout << "Express x = " + to_string(x) + " as a plaintext polynomial 0x" + x_plain.to_string() + "." << endl;

	print_line(__LINE__);
	Ciphertext x_encrypted;
	cout << "Encrypt x_plain to x_encrypted." << endl;
	encryptor.encrypt(x_plain, x_encrypted);

	cout << "    + size of freshly encrypted x: " << x_encrypted.size() << endl;
	cout << "    + noise budget in freshly encrypted x: " << decryptor.invariant_noise_budget(x_encrypted) << " bits" << endl;

	Plaintext x_decrypted;
	cout << "    + decryption of x_encrypted: ";
	decryptor.decrypt(x_encrypted, x_decrypted);
	cout << "0x" << x_decrypted.to_string() << " ...... Correct." << endl;*/

	return 0;

/**
	print_example_banner("Example: BFV Basics");

	EncryptionParameters parms(scheme_type::BFV);

	size_t poly_modulus_degree = 4096;
	parms.set_poly_modulus_degree(poly_modulus_degree);

	parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));

	parms.set_plain_modulus(256);


	auto context = SEALContext::Create(parms);

	print_line(__LINE__);
	cout << "Set encryption parameters and print" << endl;
	print_parameters(context);

	cout << endl;
	cout << "~~~~~~ A naive way to calculate 2(x^2+1)(x+1)^2. ~~~~~~" << endl;


	KeyGenerator keygen(context);
	PublicKey public_key = keygen.public_key();
	SecretKey secret_key = keygen.secret_key();

	Encryptor encryptor(context, public_key);
	Evaluator evaluator(context);
	Decryptor decryptor(context, secret_key);

	print_line(__LINE__);
	int x = 6;
	Plaintext x_plain(to_string(x));
	cout << "Express x = " + to_string(x) + " as a plaintext polynomial 0x" + x_plain.to_string() + "." << endl;

	print_line(__LINE__);
	Ciphertext x_encrypted;
	cout << "Encrypt x_plain to x_encrypted." << endl;
	encryptor.encrypt(x_plain, x_encrypted);

	cout << "    + size of freshly encrypted x: " << x_encrypted.size() << endl;
	cout << "    + noise budget in freshly encrypted x: " << decryptor.invariant_noise_budget(x_encrypted) << " bits" << endl;

	Plaintext x_decrypted;
	cout << "    + decryption of x_encrypted: ";
	decryptor.decrypt(x_encrypted, x_decrypted);
	cout << "0x" << x_decrypted.to_string() << " ...... Correct." << endl;

	print_line(__LINE__);
	cout << "Compute x_sq_plus_one (x^2+1)." << endl;
	Ciphertext x_sq_plus_one;
	evaluator.square(x_encrypted, x_sq_plus_one);
	Plaintext plain_one("1");
	evaluator.add_plain_inplace(x_sq_plus_one, plain_one);

	cout << "    + size of x_sq_plus_one: " << x_sq_plus_one.size() << endl;
	cout << "    + noise budget in x_sq_plus_one: " << decryptor.invariant_noise_budget(x_sq_plus_one) << " bits" << endl;

	Plaintext decrypted_result;

	cout << "    + decryption of x_sq_plus_one: ";
	decryptor.decrypt(x_sq_plus_one, decrypted_result);
	cout << "0x" << decrypted_result.to_string() << " ...... Correct." << endl;

	print_line(__LINE__);
	cout << "Compute x_plus_one_sq ((x+1)^2)." << endl;
	Ciphertext x_plus_one_sq;
	evaluator.add_plain(x_encrypted, plain_one, x_plus_one_sq);
	evaluator.square_inplace(x_plus_one_sq);
	cout << "    + size of x_plus_one_sq: " << x_plus_one_sq.size() << endl;
	cout << "    + noise budget in x_plus_one_sq: " << decryptor.invariant_noise_budget(x_plus_one_sq) << " bits" << endl;
	cout << "    + decryption of x_plus_one_sq: ";
	decryptor.decrypt(x_plus_one_sq, decrypted_result);
	cout << "0x" << decrypted_result.to_string() << " ...... Correct." << endl;

	print_line(__LINE__);
	cout << "Compute encrypted_result (2(x^2+1)(x+1)^2)." << endl;
	Ciphertext encrypted_result;
	Plaintext plain_two("2");
	evaluator.multiply_plain_inplace(x_sq_plus_one, plain_two);
	evaluator.multiply(x_sq_plus_one, x_plus_one_sq, encrypted_result);
	cout << "    + size of encrypted_result: " << encrypted_result.size() << endl;
	cout << "    + noise budget in encrypted_result: " << decryptor.invariant_noise_budget(encrypted_result) << " bits" << endl;
	cout << "NOTE: Decryption can be incorrect if noise budget is zero." << endl;

	cout << endl;
	cout << "~~~~~~ A better way to calculate 2(x^2+1)(x+1)^2. ~~~~~~" << endl;
*/

}

