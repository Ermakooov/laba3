#include "tableCipher.h"
#include "tableCipher.cpp"
#include <UnitTest++/UnitTest++.h>
#include <locale>

using namespace std;

SUITE(KeyTest)
{
    TEST(ValidKey) {
        CHECK_NOTHROW(TableCipher cp(4));
    }
    
    TEST(BigKey) {
        CHECK_NOTHROW(TableCipher cp(234));
    }
    
    TEST(InvalidKey) {
        CHECK_THROW(TableCipher cp(-4), cipher_error);
    }
    
    TEST(ZeroKey) {
        CHECK_THROW(TableCipher cp(0), cipher_error);
    }
}

SUITE(EncryptTest)
{
    TEST(ValidText) {
        TableCipher cipher(5);
        CHECK_EQUAL(L"ТАВТПНИМДАИИКРВЦРДИЕОДТОНАКАЬТ", 
                    cipher.encrypt(L"НИКИТАЕРМАКОВДВАДЦАТЬТРИПТОДИН"));
    }
    
    TEST(Key4ValidText) {
        TableCipher cipher(4);
        CHECK_EQUAL(L"ВИИМРТПЕР", 
                    cipher.encrypt(L"ПРИВЕТМИР"));
    }
    
    TEST(BigKeyText) {
        TableCipher cipher(234);
        CHECK_EQUAL(L"РИМТЕВИРП", 
                    cipher.encrypt(L"ПРИВЕТМИР"));
    }
    
    TEST(MixedCaseText) {
        TableCipher cipher(5);
        CHECK_EQUAL(L"ТАВТПНИМДАИИКРВЦРДИЕОДТОНАКАЬТ", 
                    cipher.encrypt(L"никитаермаковдвадцатьтриптодин"));
    }
    
    TEST(TextWithSpaces) {
        TableCipher cipher(5);
        CHECK_EQUAL(L"ТАВТПНИМДАИИКРВЦРДИЕОДТОНАКАЬТ", 
                    cipher.encrypt(L"НИКИТА ЕРМАКОВ ДВАДЦАТЬ ТРИ ПТ ОДИН"));
    }
    
    TEST(EmptyText) {
        TableCipher cipher(5);
        CHECK_THROW(cipher.encrypt(L""), cipher_error);
    }
    
    TEST(NonAlphaText) {
        TableCipher cipher(5);
        CHECK_THROW(cipher.encrypt(L"ПРИВЕТ123"), cipher_error);
    }
}

SUITE(DecryptTest)
{
    TEST(ValidText) {
        TableCipher cipher(5);
        CHECK_EQUAL(L"НИКИТАЕРМАКОВДВАДЦАТЬТРИПТОДИН", 
                    cipher.decrypt(L"ТАВТПНИМДАИИКРВЦРДИЕОДТОНАКАЬТ"));
    }
    
    TEST(Key4ValidText) {
        TableCipher cipher(4);
        CHECK_EQUAL(L"ПРИВЕТМИР", 
                    cipher.decrypt(L"ВИИМРТПЕР"));
    }
    
    TEST(EmptyText) {
        TableCipher cipher(5);
        CHECK_THROW(cipher.decrypt(L""), cipher_error);
    }
    
    TEST(NonAlphaText) {
        TableCipher cipher(5);
        CHECK_THROW(cipher.decrypt(L"ПРИВЕТ123"), cipher_error);
    }
    
    TEST(MixedCaseText) {
        TableCipher cipher(5);
        CHECK_THROW(cipher.decrypt(L"ЕВРИИРМпт"), cipher_error);
    }
    
    TEST(TextWithSpaces) {
        TableCipher cipher(5);
        CHECK_THROW(cipher.decrypt(L"ЕВРИИР МП!Т"), cipher_error);
    }
}

int main(int argc, char** argv) {
    std::locale loc("ru_RU.UTF-8");
    std::locale::global(loc);
    return UnitTest::RunAllTests();
}
