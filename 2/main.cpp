#include "tableCipher.h"
#include "tableCipher.cpp"
#include <UnitTest++/UnitTest++.h>
#include <locale>

using namespace std;

SUITE(KeyTest)
{
    TEST(ValidKey) {
        TableCipher cp(4);
        CHECK(true);
    }
    
    TEST(BigKey) {
        TableCipher cp(234);
        CHECK(true);
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
        wstring result = cipher.encrypt(L"НИКИТАЕРМАКОВДВАДЦАТЬТРИПТОДИН");
        wstring expected = L"ТАВТПНИМДАИИКРВЦРДИЕОДТОНАКАЬТ";
        CHECK(result == expected);
    }
    
    TEST(Key4ValidText) {
        TableCipher cipher(4);
        wstring result = cipher.encrypt(L"ПРИВЕТМИР");
        wstring expected = L"ВИИМРТПЕР";
        CHECK(result == expected);
    }
    
    TEST(BigKeyText) {
        TableCipher cipher(234);
        wstring result = cipher.encrypt(L"ПРИВЕТМИР");
        wstring expected = L"РИМТЕВИРП";
        CHECK(result == expected);
    }
    
    TEST(MixedCaseText) {
        TableCipher cipher(5);
        wstring result = cipher.encrypt(L"никитаермаковдвадцатьтриптодин");
        wstring expected = L"ТАВТПНИМДАИИКРВЦРДИЕОДТОНАКАЬТ";
        CHECK(result == expected);
    }
    
    TEST(TextWithSpaces) {
        TableCipher cipher(5);
        wstring result = cipher.encrypt(L"НИКИТА ЕРМАКОВ ДВАДЦАТЬ ТРИ ПТ ОДИН");
        wstring expected = L"ТАВТПНИМДАИИКРВЦРДИЕОДТОНАКАЬТ";
        CHECK(result == expected);
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
        wstring result = cipher.decrypt(L"ТАВТПНИМДАИИКРВЦРДИЕОДТОНАКАЬТ");
        wstring expected = L"НИКИТАЕРМАКОВДВАДЦАТЬТРИПТОДИН";
        CHECK(result == expected);
    }
    
    TEST(Key4ValidText) {
        TableCipher cipher(4);
        wstring result = cipher.decrypt(L"ВИИМРТПЕР");
        wstring expected = L"ПРИВЕТМИР";
        CHECK(result == expected);
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
        wstring result = cipher.decrypt(L"ЕВРИИРМпт");
        wstring expected = L"ПРИВЕТМИР";
        CHECK(result == expected);
    }
    
    TEST(TextWithSpaces) {
        TableCipher cipher(5);
        wstring result = cipher.decrypt(L"ЕВРИИР МП!Т");
        wstring expected = L"ПРИВЕТМИР";
        CHECK(result == expected);
    }
}

int main(int argc, char** argv) {
    std::locale loc("ru_RU.UTF-8");
    std::locale::global(loc);
    return UnitTest::RunAllTests();
}
