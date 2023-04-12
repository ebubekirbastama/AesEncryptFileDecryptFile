#include <iostream>
#include <fstream>
#include <aes.h>
#include <modes.h>
#include <filters.h>
#include <stdexcept>
#include <cryptlib.h>
#include <validate.h>
#include <pwdbased.h>
#include <rsa.h>
#include <osrng.h>

using namespace CryptoPP;

void EncryptFile(const std::string& inputFile, const std::string& outputFile, const std::string& password)
{
    const int KEY_SIZE = 32;
    const int BLOCK_SIZE = 16;
    const int DERIVATION_ITERATIONS = 1000;

    byte key[KEY_SIZE];
    byte iv[BLOCK_SIZE];
    byte salt[BLOCK_SIZE];

    // Salt üretme
    AutoSeededRandomPool rng;
    rng.GenerateBlock(salt, sizeof(salt));

    // Şifreleme anahtarı ve iv oluşturma
    PKCS5_PBKDF2_HMAC<SHA256> pbkdf2;
    pbkdf2.DeriveKey(key, sizeof(key), 0, (byte*)password.data(), password.size(), salt, sizeof(salt), DERIVATION_ITERATIONS);
    pbkdf2.DeriveKey(iv, sizeof(iv), 1, (byte*)password.data(), password.size(), salt, sizeof(salt), DERIVATION_ITERATIONS);

    // Dosyayı şifreleme
    try {
        CBC_Mode<AES>::Encryption encryption(key, sizeof(key), iv);
        FileSource(inputFile.c_str(), true, new StreamTransformationFilter(encryption, new FileSink(outputFile.c_str()), BlockPaddingSchemeDef::PKCS_PADDING));
    }
    catch (const Exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return;
    }

    // Salt'ı başına yazdırma
    std::ofstream ofs(outputFile, std::ios::binary | std::ios::app);
    ofs.write(reinterpret_cast<const char*>(&salt), sizeof(salt));
    ofs.close();

    std::cout << "Sifreleme tamamlandi!" << std::endl;
}

void DecryptFile(const std::string& inputFile, const std::string& outputFile, const std::string& password)
{
    const int KEY_SIZE = 32;
    const int BLOCK_SIZE = 16;
    const int DERIVATION_ITERATIONS = 1000;

    byte key[KEY_SIZE];
    byte iv[BLOCK_SIZE];
    byte salt[BLOCK_SIZE];

    // Girdi dosyasını açma
    std::ifstream ifs(inputFile, std::ios::binary);
    if (!ifs.good()) {
        throw std::runtime_error("Girdi dosyasi acilamadi!");
    }

    // Salt değerini okuma
    if (!ifs.read((char*)&salt, BLOCK_SIZE)) {
        throw std::runtime_error("Salt degeri okunamadi!");
    }

    // Şifreleme anahtarını ve iv'yi üretme
    PKCS5_PBKDF2_HMAC<SHA256> pbkdf2;
    pbkdf2.DeriveKey(key, sizeof(key), 0, (byte*)password.data(), password.size(), salt, BLOCK_SIZE, DERIVATION_ITERATIONS);
    pbkdf2.DeriveKey(iv, sizeof(iv), 1, (byte*)password.data(), password.size(), salt, BLOCK_SIZE, DERIVATION_ITERATIONS);

    // Dosyayı şifre çözme
    CBC_Mode<AES>::Decryption decryption(key, sizeof(key), iv);
    FileSource(inputFile.c_str(), true, new StreamTransformationFilter(decryption, new FileSink(outputFile.c_str())));

    std::cout << "Sifre cozme islemi tamamlandi!" << std::endl;
}

int main()
{
   
    std::string inputFile;
    std::string outputFile;
    std::string password;

    std::cout << "Girdi dosyasinin adini girin: ";
    std::getline(std::cin, inputFile);

    std::cout << "Cikti dosyasinin adini girin: ";
    std::getline(std::cin, outputFile);

    std::cout << "Parolayi Girin: ";
    std::getline(std::cin, password);

    try {
         //EncryptFile(inputFile, outputFile, password);
        DecryptFile(inputFile, outputFile, password);

        // Dosyayı çalıştırma
        char command[1024];
        snprintf(command, sizeof(command), "./%s", outputFile.c_str());
        int result = system(command);
        if (result != 0) {
            std::cerr << "Hata: Sifre cozulmus dosya calistirilamadi!" << std::endl;
        }

        // Geçici dosyayı silme
        remove(outputFile.c_str());
    }
    catch (std::exception& e) {
        std::cerr << "Hata: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
