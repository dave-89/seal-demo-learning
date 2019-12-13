#include <iostream>
#include <seal/seal.h>


using namespace std;

int main(int, char **)
{

  // setUP (common server and client)
  size_t polyModulusDegree = 8192;
  seal::EncryptionParameters encryptionParameters(
      seal::scheme_type::BFV);
  encryptionParameters.set_poly_modulus_degree(polyModulusDegree);
  encryptionParameters.set_coeff_modulus(seal::util::global_variables::default_coeff_modulus_128.at(polyModulusDegree));
  encryptionParameters.set_plain_modulus(1ULL << 32);

  auto sealContext = seal::SEALContext::Create(encryptionParameters);

  //client - create key pair
  seal::KeyGenerator keyGenerator(sealContext);
  auto publicKey = keyGenerator.public_key();
  auto secretKey = keyGenerator.secret_key();
  seal::Encryptor encryptor(sealContext, publicKey);
  seal::Decryptor decryptor(sealContext, secretKey);

  //client - create plaintext
  seal::Plaintext plainText1 ("5");
  seal::Plaintext plainText2 ("2");

  // client - encrypt stuff
  seal::Ciphertext cipherText1, cipherText2;

  encryptor.encrypt(plainText1, cipherText1);
  encryptor.encrypt(plainText2, cipherText2);

  // Server - evaluate on cipherText
  seal::Evaluator evaluator(sealContext);
  seal::Ciphertext cipherResult;
  evaluator.add(cipherText1, cipherText2, cipherResult);

  // client - decrypt the result
  seal::Plaintext plainResult;
  decryptor.decrypt(cipherResult, plainResult);

  cout << "Result: " << plainResult.to_string() << endl;

  
  

}
