#include "modAlphaCipher.cpp"
#include "modAlphaCipher.h"
#include <UnitTest++/UnitTest++.h>
#include <locale>

using namespace std;

SUITE(KeyTest)
{
    TEST(ValidKey) { 
        CHECK_NOTHROW(modAlphaCipher cp(L"НИКИТА"));
    }
    
    TEST(LongKey) { 
        CHECK_NOTHROW(modAlphaCipher cp(L"НИКИТАНИКИТАНИКИТА"));
    }
    
    TEST(LowCaseKey) { 
        CHECK_NOTHROW(modAlphaCipher cp(L"никита"));
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
        CHECK_EQUAL(L"ОЙЛЙУБЁСНБЛПГЕГБЕЧБУЭУСЙРУПЕЙО", 
                    p->encrypt(L"НИКИТАЕРМАКОВДВАДЦАТЬТРИПТОДИН"));
    }
    
    TEST_FIXTURE(KeyB_fixture, LowCaseString) {
        CHECK_EQUAL(L"ОЙЛЙУБЁСНБЛПГЕГБЕЧБУЭУСЙРУПЕЙО", 
                    p->encrypt(L"никитаермаковдвадцатьтриптодин"));
    }
    
    TEST_FIXTURE(KeyB_fixture, StringWithWhitspaceAndPunct) {
        CHECK_EQUAL(L"ОЙЛЙУБЁСНБЛПГЕГБЕЧБУЭУСЙРУПЕЙО", 
                    p->encrypt(L"НИКИТА ЕРМАКОВ, ДВАДЦАТЬ ТРИ ПТ, ОДИН"));
    }
    
    TEST_FIXTURE(KeyB_fixture, StringWithNumbers) {
        CHECK_EQUAL(L"ТОПГЬНДПЕПН", 
                    p->encrypt(L"С Новым 2025 Годом"));
    }
    
    TEST_FIXTURE(KeyB_fixture, EmptyString) {
        CHECK_THROW(p->encrypt(L""), cipher_error);
    }
    
    TEST_FIXTURE(KeyB_fixture, NoAlphaString) {
        CHECK_THROW(p->encrypt(L"1234+8765=9999"), cipher_error);
    }
    
    TEST(MaxShiftKey) {
        CHECK_EQUAL(L"МЗЙЗСЯДПЛЯЙНБГБЯГХЯСЫСПЗОСНГЗМ", 
                    modAlphaCipher(L"Я").encrypt(L"НИКИТАЕРМАКОВДВАДЦАТЬТРИПТОДИН"));
    }
}

SUITE(DecryptText)
{
    TEST_FIXTURE(KeyB_fixture, UpCaseString) {
        CHECK_EQUAL(L"НИКИТАЕРМАКОВДВАДЦАТЬТРИПТОДИН", 
                    p->decrypt(L"ОЙЛЙУБЁСНБЛПГЕГБЕЧБУЭУСЙРУПЕЙО"));
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
        CHECK_EQUAL(L"НИКИТАЕРМАКОВДВАДЦАТЬТРИПТОДИН", 
                    modAlphaCipher(L"Я").decrypt(L"МЗЙЗСЯДПЛЯЙНБГБЯГХЯСЫСПЗОСНГЗМ"));
    }
}

int main(int argc, char** argv) {
    std::locale loc("ru_RU.UTF-8");
    std::locale::global(loc);
    return UnitTest::RunAllTests();
}
