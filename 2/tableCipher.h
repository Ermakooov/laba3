#pragma once
#include <cctype>
#include <codecvt>
#include <iostream>
#include <locale>
#include <map>
#include <string>
#include <vector>
class TableCipher
{
private:
    int stolb;
    int getValidKey(const int& key);//  проверка ключа на валидности
    std::wstring getValidText(const std::wstring& text);// проверка текста на валидности
public:
    TableCipher() = delete; // запрет на конструктор по умолчанию
    TableCipher(const int& key);
    std::wstring encrypt(const std::wstring& encrypt_text);
    std::wstring decrypt(const std::wstring& decrypt_text);
};
class cipher_error : public std::invalid_argument
{
public:
    explicit cipher_error(const std::string& what_arg):
        std::invalid_argument(what_arg) {}
    explicit cipher_error(const char* what_arg):
        std::invalid_argument(what_arg) {}
};
