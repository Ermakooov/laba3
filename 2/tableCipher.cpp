#include "tableCipher.h"
using namespace std;
TableCipher::TableCipher(const int& key)
    : stolb(getValidKey(key)) {}
std::wstring TableCipher::encrypt(const std::wstring& encrypt_text)
{
    std::wstring validText = getValidText(encrypt_text);
    std::wstring table = validText; // создаем копию текста
    int len, str, index, x;
    len = validText.length(); // вычисляем длину сообщения
    str = (len - 1) / stolb + 1;
    x = 0;
    for(int i = stolb; i > 0; i--) { // проходим по столбцам в обратном порядке
        for(int j = 0; j < str; j++) {
            index = i + stolb * j; //Вычисляется индекс символа в сообщении,
            //который нужно взять из таблицы.
            if(index - 1 < len) {
                table[x] = validText[index - 1];
                x++;
            }
        }
    }
    return table;
}

std::wstring TableCipher::decrypt(const std::wstring& decrypt_text)
{
    std::wstring validText = getValidText(decrypt_text);
    std::wstring table = validText;
    int len, str, index, x;
    len = validText.length();
    str = (len - 1) / stolb + 1;
    x = 0;
    for(int i = stolb; i > 0; i--) {
        for(int j = 0; j < str; j++) {
            index = i + stolb * j;
            if(index - 1 < len) {
                table[index - 1] = validText[x];
                x++;
            }
        }
    }
    return table;
}

int TableCipher::getValidKey(const int& key)
{
    if (key <= 0)
        throw cipher_error("Invalid key");
    return key;
}

std::wstring TableCipher::getValidText(const std::wstring& text)
{
    if (text.empty())
        throw cipher_error("Empty text");

    std::wstring validText;
    for (auto c : text) {
        if (iswalpha(c)) {
            validText += towupper(c); // Приводим символ к верхнему регистру
        } else if (!iswspace(c) && !iswpunct(c)) {
            // Если символ не является буквой, пробелом или знаком препинания, 		 	выбрасываем исключение
            throw cipher_error("Invalid text");
        }
    }

    if (validText.empty())
        throw cipher_error("Invalid text");

    return validText;
}


