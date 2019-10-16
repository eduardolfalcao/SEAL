//libs for reading csv
#include <iostream>
#include <fstream>
#include <vector>
#include <iterator>
#include <string>
#include <algorithm>
#include <boost/algorithm/string.hpp>

#include "examples.h"
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
	print_vector(output);

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

	for(Ciphertext xRow : x){
		decryptAndPrint(decryptor,encoder,xRow,"xRow");
	
		Ciphertext theta_temp = theta;

		evaluator->multiply_inplace(theta_temp,xRow);
		evaluator->relinearize_inplace(theta_temp, relin_keys);
		evaluator->rescale_to_next_inplace(theta_temp);

		Ciphertext sum;

	}

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

	//sigmoid
	/*print_line(__LINE__);
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

	Plaintext plain_res;
	print_line(__LINE__);
	cout << "Decrypt and decode." << endl;
	decryptor.decrypt(enc_sq, plain_res);
	vector<double> output;
	encoder.decode(plain_res, output);
	cout << "    + Result vector ...... Correct." << endl;
	print_vector(output, 4, 10);*/



	//hypothesis
	print_line(__LINE__);
	vector<vector<double>> inputMatrix{ 
				{0.5, 0.5, 0.5},
				{0.5, 0.5, 0.5},
				{0.5, 0.5, 0.5}	};
	vector<Plaintext> plain_x;
	for(vector<double> inputVector : inputMatrix){
		Plaintext plain_v;
		encoder.encode(inputVector, scale, plain_v);
		plain_x.push_back(plain_v);
	}
	vector<Ciphertext> encrypted_x_vec;
	for(Plaintext plain : plain_x){
		Ciphertext encrypted_x;
		encryptor.encrypt(plain, encrypted_x);
		encrypted_x_vec.push_back(encrypted_x);		
	}
	
	vector<double> inputVector{ 0.5, 0.5, 0.5 };
	Plaintext plain_theta;
	encoder.encode(inputVector, scale, plain_theta);
	Ciphertext encrypted_theta;
	encryptor.encrypt(plain_theta, encrypted_theta);

	Ciphertext hx = h(encrypted_x_vec, encrypted_theta, &evaluator, &encoder, &decryptor, relin_keys, scale, &context);


	/*print_line(__LINE__);
	cout << "Encode input vector." << endl;
	encoder.encode(input, scale, plain);

	Ciphertext encrypted;
	print_line(__LINE__);
	cout << "Encrypt input vector and square." << endl;
	encryptor.encrypt(plain, encrypted);

	Ciphertext enc_sq = g(encrypted, &evaluator, &encoder,&decryptor, relin_keys, scale, &context);

	Plaintext plain_res;
	print_line(__LINE__);
	cout << "Decrypt and decode." << endl;
	decryptor.decrypt(enc_sq, plain_res);
	vector<double> output;
	encoder.decode(plain_res, output);
	cout << "    + Result vector ...... Correct." << endl;
	print_vector(output, 4, 10);*/
	
		
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




	return 0;


}

