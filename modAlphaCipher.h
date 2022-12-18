/**
* @file modAlphaCipher.h
* @author Сергиенко И.И.
* @version 1.0
* @brief Описание класса modAlphaCipher
* @date 10.11.2022
* @copyright ИБСТ ПГУ
*/
#pragma once
#include <vector>
#include <string>
#include <map>
#include <locale>
using namespace std;
/**  @brief  Класс, который реализует шифрование методом "Гронсвельда"
* @warning Работает только с русскоязычными сообщениями
* */
class modAlphaCipher
{
private:
/// @brief  Используемый алфавит по порядку для сообщений, которые шифруются методом "Гронсвельда"
    std::wstring numAlpha = L"АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ";
    /// @brief  Ассоциативный массив "номер по символу"
    std::map <char,int> alphaNum; //ассоциативный массив "номер по символу"
    /// @brief  Атрибут, хранящий в себе ключ для шифрования и расшифрования
    std::vector <int> key; //ключ
    /** @brief  Преобразование строки в вектор
    * @details В вектор типа "int" с именем "result" записываются числа, которые являются индексами алфавита "numAlpha",применяемый для строки,
    * которая поступила на вход.
    * @code
    *  vector<int> result;
    *   for(auto c:s) {
    *       result.push_back(alphaNum[c]);
    *   }
    * @endcode
    * @return std::vector <int>, в котором хранятся индексы букв сообщения из алфавита "numAlpha"
    */
    std::vector<int> convert(const std::wstring& s);//преобразование строка-вектор
    /** @brief Преобразование вектора в строку
    * @details В переменную типа "wstring" с именем "result" записывается строка согласно индексам каждой буквы алфавита "numAlpha".
    * Индексы хранятся в векторе типа "int", который поступил на вход.
    * @code
    *  wstring result;
    *   for(auto i:v) {
    *       result.push_back(numAlpha[i]);
    *   }
    * @endcode
    * @return строка текста типа "wstring"
    */
    std::wstring convert(const std::vector<int>& v);//преобразование вектор-строка
    /** @brief  Валидация ключа
    * @details Сначала введённый ключ проверяется на пустоту при помощи обычного условия. Если ключ не пустой, то
    * он проверяется на наличие недопустимых символов.
    * @warning Строчные буквы алфавита переводятся в прописные.
    * @param std::wstring s - ключ, который нужно проверить на наличие ошибок, в виде строки
    * @throw cipher_error, если ключ пустой или в нём присутствуют недопустимые символы
    * @return Ключ в виде строки типа "wstring", который успешно прошёл валидацию
    */
    std::wstring getValidKey(const std::wstring & s);
    /** @brief Валидация текста при шифровании или расшифровании
     * @details Сначала введённый текст проверяется на пустоту при помощи обычного условия. Если текст не пустой, то
     * он проверяется на наличие недопустимых символов.
     * @warning Строчные буквы алфавита переводятся в прописные.
     * @param std::wstring s - строка текста для шифрования или расшифрования, которая проверяется на наличие ошибок
     * @throw cipher_error, если текст является пустым или в нём присутствуют недопустимые символы
     * @return Текст в виде строки типа "wstring", который успешно прошёл валидацию
     */
    std::wstring getValidText(const std::wstring & s);
public:
/// @brief Запрещённый конструктор без параметров
    modAlphaCipher()=delete;//запретим конструктор без параметров
    /** @brief  Конструктор для ключа
     *    @details Цикл for построен по строке-алфавиту и на каждом шаге добавляет в ассоциативный массив
     *  символ и его номер.
     *  @code
     *     for (unsigned i=0; i<numAlpha.size(); i++) {
     *          alphaNum[numAlpha[i]]=i;
     *      }
     *  @endcode
     *  @param std::wstring - ключ в виде строки
     */
    modAlphaCipher(const std::wstring& skey);    //конструктор для установки ключа
    /**
    * @brief Метод для шифрования
    * @details Здесь сначала формируется вектор work из строки открытого текста с помощью метода
    *   convert().  А также происходит проверка текста на наличие ошибки при помощи метода getValidAlphabetText().
    *  @code
    *       vector<int> work = convert(getValidAlphabetText(open_text));
    * @endcode
    *  Затем в цикле к каждому элементу вектора прибавляется элемент ключа по модулю размера
    *   алфавита. Так как ключ может быть короче текста, то при индексации ключа выполняется операция
    *   по модулю размера ключа. Это позволяет использовать ключ циклически на длинных сообщениях.
    *  @code
    *   for(unsigned i=0; i < work.size(); i++) {
    *      work[i] = (work[i] + key[i % key.size()]) % alphaNum.size();
    *   }
    * @endcode
    * Далее, при возврате значения, вектор work опять преобразуется в строку.
    * @param std::wstring open_text - сообщение, которое нужно зашифровать
    * @throw cipher_error , если строка, которая поступила на вход пустая или в ней есть недопустимые символы
    * @return строка зашифрованного текста типа "wstring"
    */
    std::wstring encrypt(const std::wstring& open_text);  //зашифрование
    /**
     * @brief Метод, предназначенный для расшифрования
     * @details Здесь сначала формируется вектор work из строки  щифратекста с помощью метода
     *   convert().  А также происходит проверка шифротекста на наличие ошибки при помощи метода getValidAlphabetText().
     *  @code
     *       vector<int> work = convert(getValidAlphabetText(cipher_text));
     * @endcode
     *  Если при зашифровывании мы прибавляли значение ключа, то при расшифровывании значения ключа надо вычитать. А чтобы не
     *  получить отрицательных значений, выполняется еще прибавление значения модуля, так как такое
     *  прибавление не влияет на результат модулю.
     *  @code
     *   for(unsigned i=0; i < work.size(); i++) {
     *           work[i] = (work[i] + alphaNum.size() - key[i % key.size()]) % alphaNum.size();
     *   }
     * @endcode
     *
     *@param std::wstring cipher_text - сообщение, которое нужно расшифровать
     * @throw cipher_error , если строка, которая поступила на вход пустая или в ней есть недопустимые символы
     * @return  строка расшифрованного текста типа "wstring"
     */
    std::wstring decrypt(const std::wstring& cipher_text);//расшифрование
};
/// @brief Класс, предназначенный для обработки исключений
class cipher_error: public std::invalid_argument
{
public:
    explicit cipher_error (const std::string& what_arg):
        std::invalid_argument(what_arg) {}
    explicit cipher_error (const char* what_arg):
        std::invalid_argument(what_arg) {}
};