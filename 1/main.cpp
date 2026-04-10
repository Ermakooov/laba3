#include "modAlphaCipher.cpp"
#include "modAlphaCipher.h"
#include <UnitTest++/UnitTest++.h>
#include <locale>

using namespace std;

SUITE(KeyTest)
{
    TEST(ValidKey) {
        modAlphaCipher cp(L"НИКИТА");
        CHECK(true);
    }
    
    TEST(LongKey) {
        modAlphaCipher cp(L"НИКИТАНИКИТАНИКИТА");
        CHECK(true);
    }
    
    TEST(LowCaseKey) {
        modAlphaCipher cp(L"никита");
        CHECK(true);
    }
    
    TEST(DigitsInKey) {
        CHECK_THROW(modAlphaCipher cp(L"Б1"), cipher_error);
    }
    
    TEST(PunctuationInKey) {
        CHECK_THROW(modAlphaCipher cp(L"Б,С"), cipher_error);
    }
    
    TEST(WhitespaceInKey) {
        CHECK_THROW(modAlphaCipher cp(L"Б С"), cipher_error);
    }
    
    TEST(EmptyKey) {
        CHECK_THROW(modAlphaCipher cp(L""), cipher_error);
    }
    
    TEST(WeakKey) {
        CHECK_THROW(modAlphaCipher cp(L"ААА"), cipher_error);
    }
}

struct KeyB_fixture {
    modAlphaCipher* p;
    KeyB_fixture() {
        p = new modAlphaCipher(L"Б");
    }
    ~KeyB_fixture() {
        delete p;
    }
};

SUITE(EncryptTest)
{
    TEST_FIXTURE(KeyB_fixture, UpCaseString) {
        wstring result = p->encrypt(L"НИКИТАЕРМАКОВДВАДЦАТЬТРИПТОДИН");
        wstring expected = L"ОЙЛЙУБЁСНБЛПГЕГБЕЧБУЭУСЙРУПЕЙО";
        CHECK(result == expected);
    }
    
    TEST_FIXTURE(KeyB_fixture, LowCaseString) {
        wstring result = p->encrypt(L"никитаермаковдвадцатьтриптодин");
        wstring expected = L"ОЙЛЙУБЁСНБЛПГЕГБЕЧБУЭУСЙРУПЕЙО";
        CHECK(result == expected);
    }
    
    TEST_FIXTURE(KeyB_fixture, StringWithWhitspaceAndPunct) {
        wstring result = p->encrypt(L"НИКИТА ЕРМАКОВ, ДВАДЦАТЬ ТРИ ПТ, ОДИН");
        wstring expected = L"ОЙЛЙУБЁСНБЛПГЕГБЕЧБУЭУСЙРУПЕЙО";
        CHECK(result == expected);
    }
    
    TEST_FIXTURE(KeyB_fixture, StringWithNumbers) {
        wstring result = p->encrypt(L"С Новым 2025 Годом");
        wstring expected = L"ТОПГЬНДПЕПН";
        CHECK(result == expected);
    }
    
    TEST_FIXTURE(KeyB_fixture, EmptyString) {
        CHECK_THROW(p->encrypt(L""), cipher_error);
    }
    
    TEST_FIXTURE(KeyB_fixture, NoAlphaString) {
        CHECK_THROW(p->encrypt(L"1234+8765=9999"), cipher_error);
    }
    
    TEST(MaxShiftKey) {
        wstring result = modAlphaCipher(L"Я").encrypt(L"НИКИТАЕРМАКОВДВАДЦАТЬТРИПТОДИН");
        wstring expected = L"МЗЙЗСЯДПЛЯЙНБГБЯГХЯСЫСПЗОСНГЗМ";
        CHECK(result == expected);
    }
}

SUITE(DecryptText)
{
    TEST_FIXTURE(KeyB_fixture, UpCaseString) {
        wstring result = p->decrypt(L"ОЙЛЙУБЁСНБЛПГЕГБЕЧБУЭУСЙРУПЕЙО");
        wstring expected = L"НИКИТАЕРМАКОВДВАДЦАТЬТРИПТОДИН";
        CHECK(result == expected);
    }
    
    TEST_FIXTURE(KeyB_fixture, LowCaseString) {
        CHECK_THROW(p->decrypt(L"ЫРМИмиыфтушвыатам"), cipher_error);
    }
    
    TEST_FIXTURE(KeyB_fixture, WhitespaceString) {
        CHECK_THROW(p->decrypt(L"ЫИР МИМ ИЫФ ТУШ ВЫА ТАМ"), cipher_error);
    }
    
    TEST_FIXTURE(KeyB_fixture, DigitsString) {
        CHECK_THROW(p->decrypt(L"ЫРМИмиыфт24146ушвыатам"), cipher_error);
    }
    
    TEST_FIXTURE(KeyB_fixture, PunctString) {
        CHECK_THROW(p->decrypt(L"ЫРМИмиы,фтушвыатам"), cipher_error);
    }
    
    TEST_FIXTURE(KeyB_fixture, EmptyString) {
        CHECK_THROW(p->decrypt(L""), cipher_error);
    }
    
    TEST(MaxShiftKey) {
        wstring result = modAlphaCipher(L"Я").decrypt(L"МЗЙЗСЯДПЛЯЙНБГБЯГХЯСЫСПЗОСНГЗМ");
        wstring expected = L"НИКИТАЕРМАКОВДВАДЦАТЬТРИПТОДИН";
        CHECK(result == expected);
    }
}

int main(int argc, char** argv) {
    std::locale loc("ru_RU.UTF-8");
    std::locale::global(loc);
    return UnitTest::RunAllTests();
}
